// Vaatimusrekisteri – on-premise-palvelin
// Tarjoaa staattisen käyttöliittymän ja REST-rajapinnan, joka tallentaa
// datan levylle (data/db.json). Useampi käyttäjä voi käyttää samaa
// palvelinta samanaikaisesti; data on kaikille yhteinen.

require("dotenv").config();

const express = require("express");
const fs = require("fs");
const https = require("https");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
// Natiivi HTTPS on valinnainen: käytettävissä API-avain kulkee (X-API-Key)
// selkeätekstinä, joten se on suojattu vain jos liikenne kulkee TLS:n yli —
// joko tämän kautta tai edessä olevan reverse proxyn (nginx/IIS/Caddy)
// kautta. Oletuksena kumpaakaan HTTPS_CERT_FILE/HTTPS_KEY_FILE-muuttujaa ei
// ole asetettu, jolloin palvelin käynnistyy ennallaan pelkkänä HTTP-
// palvelimena (esim. reverse proxyn taakse tarkoitetut asennukset) — ks.
// "Käyttöönotto (on-premise)" vaatimusmäärittelyssä.
const HTTPS_CERT_FILE = process.env.HTTPS_CERT_FILE;
const HTTPS_KEY_FILE = process.env.HTTPS_KEY_FILE;
const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "db.json");

// ---------- API-avaimet ----------
// API_KEYS-ympäristömuuttuja:
// "Nimi:avain:vanhenemispäivä:oletusOmistaja:oletusYritys:käyttöoikeus,..."
// Kolme viimeistä osaa ovat valinnaisia. käyttöoikeus on:
// - "readonly", jos avain saa vain lukea ja tulostaa muttei lisätä/muokata/
//   poistaa mitään;
// - "no-admin", jos avain saa lisätä/muokata/poistaa vaatimuksia ja listoja
//   normaalisti, mutta ei saa muokata taustatietoja — kategorioita,
//   alakategorioita, omistajia, yrityksiä tai fraaseja (ks. ADMIN_DATA_PATHS);
// - muuten (tai jätettynä pois) avaimella on täydet oikeudet.
// Jos muuttuja puuttuu tai on tyhjä, /api/*-rajapinta ei vaadi autentikointia.
function parseApiKeys(raw) {
  if (!raw) return [];
  return raw
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [name, key, expiresAt, defaultIndustry, defaultCompany, accessLevel] = entry.split(":").map((s) => (s || "").trim());
      const level = (accessLevel || "").toLowerCase();
      return {
        name,
        key,
        expiresAt,
        defaultIndustry: defaultIndustry || "",
        defaultCompany: defaultCompany || "",
        readOnly: level === "readonly",
        noAdmin: level === "no-admin",
      };
    })
    .filter((k) => k.key);
}

// Reitit, jotka muokkaavat taustatietoja (kategoriat/alakategoriat/
// omistajat/yritykset/fraasit) — joko suoraan (CRUD-reitit) tai
// sivuvaikutuksena (seed-alustus ja "Tee yhteistyötä" -tuonti voivat
// molemmat luoda uusia kategorioita/alakategorioita/omistajia). "no-admin"
// -avain saa tehdä GET-pyyntöjä normaalisti (koko data, taustatiedot
// mukaan lukien, tulee yhden GET /api/state -kutsun mukana, eikä sitä
// rajoiteta) mutta ei mitään kirjoittavaa pyyntöä näihin polkuihin.
const ADMIN_DATA_PATHS = ["/categories", "/subcategories", "/industries", "/companies", "/phrases", "/procurement-targets", "/seed", "/collaborate/import"];

function isAdminDataPath(reqPath) {
  return ADMIN_DATA_PATHS.some((p) => reqPath === p || reqPath.startsWith(p + "/"));
}

const API_KEYS = parseApiKeys(process.env.API_KEYS);

// Vakioaikainen merkkijonovertailu — estää ajoitushyökkäyksen, jossa
// avainta arvattaisiin merkki kerrallaan vastausaikoja mittaamalla.
// timingSafeEqual vaatii samanpituiset puskurit, joten molemmat
// merkkijonot tiivistetään ensin kiinteän mittaisiksi (sha256) sen sijaan
// että alkuperäisten pituuksien mahdollinen ero paljastuisi jo ennen
// vertailua.
function timingSafeStringEqual(a, b) {
  const bufA = crypto.createHash("sha256").update(String(a)).digest();
  const bufB = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(bufA, bufB);
}

function findValidApiKey(key) {
  const today = nowIso().slice(0, 10); // YYYY-MM-DD
  return API_KEYS.find((k) => timingSafeStringEqual(k.key, key) && (!k.expiresAt || k.expiresAt >= today));
}

function requireApiKey(req, res, next) {
  if (API_KEYS.length === 0) return next(); // autentikointi ei käytössä
  const key = req.get("X-API-Key");
  if (!key) return res.status(401).json({ error: "API-avain puuttuu (header X-API-Key)" });
  const match = API_KEYS.find((k) => timingSafeStringEqual(k.key, key));
  if (!match) return res.status(401).json({ error: "API-avain on virheellinen" });
  if (!findValidApiKey(key)) return res.status(401).json({ error: "API-avain on vanhentunut" });
  if (match.readOnly && req.method !== "GET") {
    return res.status(403).json({ error: "API-avain on vain luku -avain: tietoja voi katsella ja tulostaa, mutta ei lisätä, muokata tai poistaa." });
  }
  if (match.noAdmin && req.method !== "GET" && isAdminDataPath(req.path)) {
    return res.status(403).json({ error: "API-avaimella ei ole oikeutta muokata taustatietoja (kategoriat, alakategoriat, omistajat, yritykset, fraasit)." });
  }
  req.apiKeyInfo = match;
  next();
}

// Ratkaisee uuden listan oletusyrityksen id:n: avaimen oma oletusyritys
// (nimellä haettuna) voittaa, muuten käytetään järjestelmän globaalia
// oletusyritystä ("isDefault"), muuten tyhjä.
function resolveDefaultCompanyId(req) {
  const keyCompanyName = req.apiKeyInfo && req.apiKeyInfo.defaultCompany;
  if (keyCompanyName) {
    const keyCompany = db.companies.find((c) => c.name.toLowerCase() === keyCompanyName.toLowerCase());
    if (keyCompany) return keyCompany.id;
  }
  const defaultCompany = db.companies.find((c) => c.isDefault);
  return defaultCompany ? defaultCompany.id : "";
}

// ---------- Tallennus ----------
function emptyDb() {
  return { requirements: [], categories: [], subcategories: [], industries: [], companies: [], phrases: [], procurementTargets: [], lists: [] };
}

function loadDb() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(emptyDb(), null, 2));
  }
  try {
    var loaded = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    if (!loaded.subcategories) loaded.subcategories = [];
    if (!loaded.industries) loaded.industries = [];
    if (!loaded.companies) loaded.companies = [];
    if (!loaded.phrases) loaded.phrases = [];
    if (!loaded.procurementTargets) loaded.procurementTargets = [];
    return loaded;
  } catch (e) {
    console.error("Virhe data-tiedoston luvussa, aloitetaan tyhjästä:", e);
    return emptyDb();
  }
}

let db = loadDb();

// Kirjoitukset jonotetaan, jotta samanaikaiset pyynnöt eivät riko tiedostoa.
let writeQueue = Promise.resolve();
function persist() {
  writeQueue = writeQueue.then(
    () =>
      new Promise((resolve, reject) => {
        fs.writeFile(DATA_FILE, JSON.stringify(db, null, 2), (err) => {
          if (err) reject(err);
          else resolve();
        });
      })
  );
  return writeQueue;
}

function uid() {
  return crypto.randomUUID();
}

function nowIso() {
  return new Date().toISOString();
}

// ---------- Sovellus ----------
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use("/api", requireApiKey);

// Koko tila kerralla (käytetään alkulatauksessa ja pollauksessa).
// apiKeyInfo ei ole osa tallennettua dataa — se lasketaan pyynnön
// X-API-Key-headerista jokaisella kutsulla erikseen.
app.get("/api/state", (req, res) => {
  const info = req.apiKeyInfo;
  res.json(Object.assign({}, db, {
    apiKeyInfo: info ? { industry: info.defaultIndustry || "", companyName: info.defaultCompany || "", readOnly: !!info.readOnly, noAdmin: !!info.noAdmin } : null,
  }));
});

// --- Vaatimukset ---
app.post("/api/requirements", (req, res) => {
  const { text, category, subcategory, industry, mandatory, type, note, acceptanceCondition, procurementTargets } = req.body || {};
  if (!text || !category || !industry) return res.status(400).json({ error: "text, category ja industry ovat pakollisia" });
  const createdBy = req.apiKeyInfo ? req.apiKeyInfo.name : "";
  const doc = { id: uid(), text, category, subcategory: subcategory || "", industry, mandatory: !!mandatory, type: type || (mandatory ? "mandatory" : "optional"), note: note || "", acceptanceCondition: acceptanceCondition || "", procurementTargets: Array.isArray(procurementTargets) ? procurementTargets : [], createdBy, createdAt: nowIso() };
  db.requirements.push(doc);
  persist().then(() => res.status(201).json(doc)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.put("/api/requirements/:id", (req, res) => {
  const r = db.requirements.find((x) => x.id === req.params.id);
  if (!r) return res.status(404).json({ error: "Vaatimusta ei löytynyt" });
  // lisääjä/muokkaaja luetaan aina autentikoidusta API-avaimesta, ei
  // koskaan pyynnön rungosta — muuten tiedon voisi väärentää.
  const { createdBy, updatedBy, updatedAt, ...rest } = req.body || {};
  Object.assign(r, rest);
  r.updatedBy = req.apiKeyInfo ? req.apiKeyInfo.name : "";
  r.updatedAt = nowIso();
  persist().then(() => res.json(r)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.delete("/api/requirements/:id", (req, res) => {
  const id = req.params.id;
  db.requirements = db.requirements.filter((x) => x.id !== id);
  db.lists.forEach((l) => {
    l.itemIds = (l.itemIds || []).filter((x) => x !== id);
    if (l.itemNotes) delete l.itemNotes[id];
    if (l.itemAcceptanceConditions) delete l.itemAcceptanceConditions[id];
  });
  persist().then(() => res.status(204).end()).catch((e) => res.status(500).json({ error: String(e) }));
});

// --- Kategoriat ---
app.post("/api/categories", (req, res) => {
  const { name } = req.body || {};
  if (!name) return res.status(400).json({ error: "name on pakollinen" });
  const doc = { id: uid(), name, createdAt: nowIso() };
  db.categories.push(doc);
  persist().then(() => res.status(201).json(doc)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.put("/api/categories/:id", (req, res) => {
  const c = db.categories.find((x) => x.id === req.params.id);
  if (!c) return res.status(404).json({ error: "Kategoriaa ei löytynyt" });
  const oldName = c.name;
  const newName = (req.body || {}).name;
  if (newName) {
    c.name = newName;
    if (newName !== oldName) {
      db.requirements.forEach((r) => {
        if (r.category === oldName) r.category = newName;
      });
    }
  }
  persist().then(() => res.json(c)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.delete("/api/categories/:id", (req, res) => {
  db.categories = db.categories.filter((x) => x.id !== req.params.id);
  persist().then(() => res.status(204).end()).catch((e) => res.status(500).json({ error: String(e) }));
});

// --- Alakategoriat ---
app.post("/api/subcategories", (req, res) => {
  const { name } = req.body || {};
  if (!name) return res.status(400).json({ error: "name on pakollinen" });
  const doc = { id: uid(), name, createdAt: nowIso() };
  db.subcategories.push(doc);
  persist().then(() => res.status(201).json(doc)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.put("/api/subcategories/:id", (req, res) => {
  const s = db.subcategories.find((x) => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: "Alakategoriaa ei löytynyt" });
  const oldName = s.name;
  const newName = (req.body || {}).name;
  if (newName) {
    s.name = newName;
    if (newName !== oldName) {
      db.requirements.forEach((r) => {
        if (r.subcategory === oldName) r.subcategory = newName;
      });
    }
  }
  persist().then(() => res.json(s)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.delete("/api/subcategories/:id", (req, res) => {
  db.subcategories = db.subcategories.filter((x) => x.id !== req.params.id);
  persist().then(() => res.status(204).end()).catch((e) => res.status(500).json({ error: String(e) }));
});

// --- Omistajat (kentän/rajapinnan nimi "industry" on historiallinen, ks. docs/vaatimusmaarittely.md) ---
app.post("/api/industries", (req, res) => {
  const { name, responsibleTitle } = req.body || {};
  if (!name || !responsibleTitle) return res.status(400).json({ error: "name ja responsibleTitle ovat pakollisia" });
  const doc = { id: uid(), name, responsibleTitle, createdAt: nowIso() };
  db.industries.push(doc);
  persist().then(() => res.status(201).json(doc)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.put("/api/industries/:id", (req, res) => {
  const ind = db.industries.find((x) => x.id === req.params.id);
  if (!ind) return res.status(404).json({ error: "Omistajaa ei löytynyt" });
  const oldName = ind.name;
  const { name, responsibleTitle } = req.body || {};
  if (name) {
    ind.name = name;
    if (name !== oldName) {
      db.requirements.forEach((r) => {
        if (r.industry === oldName) r.industry = name;
      });
      db.procurementTargets.forEach((t) => {
        if (t.industry === oldName) t.industry = name;
      });
    }
  }
  if (responsibleTitle) ind.responsibleTitle = responsibleTitle;
  persist().then(() => res.json(ind)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.delete("/api/industries/:id", (req, res) => {
  db.industries = db.industries.filter((x) => x.id !== req.params.id);
  persist().then(() => res.status(204).end()).catch((e) => res.status(500).json({ error: String(e) }));
});

// --- Yritykset ---
app.post("/api/companies", (req, res) => {
  const { name, businessId, postalAddress, postalCode, city, phone, email, isDefault } = req.body || {};
  if (!name) return res.status(400).json({ error: "name on pakollinen" });
  if (isDefault) db.companies.forEach((c) => { c.isDefault = false; });
  const doc = {
    id: uid(),
    name,
    businessId: businessId || "",
    postalAddress: postalAddress || "",
    postalCode: postalCode || "",
    city: city || "",
    phone: phone || "",
    email: email || "",
    isDefault: !!isDefault,
    createdAt: nowIso(),
  };
  db.companies.push(doc);
  persist().then(() => res.status(201).json(doc)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.put("/api/companies/:id", (req, res) => {
  const c = db.companies.find((x) => x.id === req.params.id);
  if (!c) return res.status(404).json({ error: "Yritystä ei löytynyt" });
  const body = req.body || {};
  if (body.isDefault) db.companies.forEach((x) => { x.isDefault = false; });
  Object.assign(c, body);
  persist().then(() => res.json(c)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.delete("/api/companies/:id", (req, res) => {
  db.companies = db.companies.filter((x) => x.id !== req.params.id);
  persist().then(() => res.status(204).end()).catch((e) => res.status(500).json({ error: String(e) }));
});

// --- Listat ---
app.post("/api/lists", (req, res) => {
  const doc = {
    id: uid(),
    name: "Uusi lista",
    notes: "",
    contactName: "",
    contactPhone: "",
    contactEmail: "",
    companyId: resolveDefaultCompanyId(req),
    procurementTargets: [],
    itemIds: [],
    itemNotes: {},
    itemAcceptanceConditions: {},
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
  db.lists.unshift(doc);
  persist().then(() => res.status(201).json(doc)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.put("/api/lists/:id", (req, res) => {
  const l = db.lists.find((x) => x.id === req.params.id);
  if (!l) return res.status(404).json({ error: "Listaa ei löytynyt" });
  Object.assign(l, req.body || {}, { updatedAt: nowIso() });
  persist().then(() => res.json(l)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.delete("/api/lists/:id", (req, res) => {
  db.lists = db.lists.filter((x) => x.id !== req.params.id);
  persist().then(() => res.status(204).end()).catch((e) => res.status(500).json({ error: String(e) }));
});

// --- Fraasit (valmiit tekstipohjat vaatimuksen tekstin syöttämisen avuksi) ---
// Fraasiin ei viitata mistään muualta (ei id:llä eikä nimellä) — sen teksti
// vain kopioidaan uuden vaatimuksen tekstikenttään, joten poistolle ei
// tarvita käytössä-olevan-eston kaltaista liiketoimintasääntöä.
app.post("/api/phrases", (req, res) => {
  const { text, category, subcategory } = req.body || {};
  if (!text) return res.status(400).json({ error: "text on pakollinen" });
  const doc = { id: uid(), text, category: category || "", subcategory: subcategory || "", createdAt: nowIso() };
  db.phrases.push(doc);
  persist().then(() => res.status(201).json(doc)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.put("/api/phrases/:id", (req, res) => {
  const p = db.phrases.find((x) => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: "Fraasia ei löytynyt" });
  const { text, category, subcategory } = req.body || {};
  if (text) p.text = text;
  if (category !== undefined) p.category = category || "";
  if (subcategory !== undefined) p.subcategory = subcategory || "";
  persist().then(() => res.json(p)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.delete("/api/phrases/:id", (req, res) => {
  db.phrases = db.phrases.filter((x) => x.id !== req.params.id);
  persist().then(() => res.status(204).end()).catch((e) => res.status(500).json({ error: String(e) }));
});

// --- Hankinnan kohteet (sidottu Omistajaan nimellä — ainoa kokoelma, joka
// viittaa toiseen taustatietokokoelmaan; kategoria/alakategoria/omistaja
// ovat kaikki tasaisia eivätkä viittaa toisiinsa, ks. docs) ---
app.post("/api/procurement-targets", (req, res) => {
  const { name, industry } = req.body || {};
  if (!name || !industry) return res.status(400).json({ error: "name ja industry ovat pakollisia" });
  const doc = { id: uid(), name, industry, createdAt: nowIso() };
  db.procurementTargets.push(doc);
  persist().then(() => res.status(201).json(doc)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.put("/api/procurement-targets/:id", (req, res) => {
  const t = db.procurementTargets.find((x) => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: "Hankinnan kohdetta ei löytynyt" });
  const oldName = t.name;
  const { name, industry } = req.body || {};
  if (name) {
    t.name = name;
    if (name !== oldName) {
      db.requirements.forEach((r) => {
        const arr = r.procurementTargets || [];
        const idx = arr.indexOf(oldName);
        if (idx !== -1) arr[idx] = name;
      });
      db.lists.forEach((l) => {
        if (l.procurementTargets) {
          const idx2 = l.procurementTargets.indexOf(oldName);
          if (idx2 !== -1) l.procurementTargets[idx2] = name;
        } else if (l.procurementTarget === oldName) {
          // Taaksepäinyhteensopivuus: dokumentit, jotka on luotu ennen
          // monivalintaa, kantavat vielä vanhaa yksittäisarvoista kenttää.
          l.procurementTarget = name;
        }
      });
    }
  }
  if (industry) t.industry = industry;
  persist().then(() => res.json(t)).catch((e) => res.status(500).json({ error: String(e) }));
});

app.delete("/api/procurement-targets/:id", (req, res) => {
  db.procurementTargets = db.procurementTargets.filter((x) => x.id !== req.params.id);
  persist().then(() => res.status(204).end()).catch((e) => res.status(500).json({ error: String(e) }));
});

// ---------- Seed-data (kategoriat/alakategoriat/omistajat/fraasit) ----------
// data/seed.json on ihmisen muokattava mallitiedosto (ei gitignoroitu,
// toisin kuin data/db.json). POST /api/seed lisää siitä vain ne rivit,
// joita ei jo löydy järjestelmästä (nimivertailu, case-insensitive;
// fraaseille tekstin vertailu, koska fraaseilla ei muuten ole
// uniikkiusvaatimusta) — ei koskaan muokkaa tai poista olemassa olevaa
// dataa, joten toimenpiteen voi ajaa turvallisesti uudelleen.
const SEED_FILE = path.join(DATA_DIR, "seed.json");

app.post("/api/seed", (req, res) => {
  let seed;
  try {
    seed = JSON.parse(fs.readFileSync(SEED_FILE, "utf8"));
  } catch (e) {
    return res.status(404).json({ error: "Seed-tiedostoa (data/seed.json) ei löytynyt tai se on virheellinen: " + String(e) });
  }

  const result = {};

  const existingCategoryNames = new Set(db.categories.map((c) => c.name.toLowerCase()));
  const newCategories = (seed.categories || []).filter((name) => !existingCategoryNames.has(String(name).toLowerCase()));
  newCategories.forEach((name) => db.categories.push({ id: uid(), name, createdAt: nowIso() }));
  result.categories = { added: newCategories.length, skipped: (seed.categories || []).filter((name) => existingCategoryNames.has(String(name).toLowerCase())) };

  const existingSubcategoryNames = new Set(db.subcategories.map((s) => s.name.toLowerCase()));
  const newSubcategories = (seed.subcategories || []).filter((name) => !existingSubcategoryNames.has(String(name).toLowerCase()));
  newSubcategories.forEach((name) => db.subcategories.push({ id: uid(), name, createdAt: nowIso() }));
  result.subcategories = { added: newSubcategories.length, skipped: (seed.subcategories || []).filter((name) => existingSubcategoryNames.has(String(name).toLowerCase())) };

  const existingIndustryNames = new Set(db.industries.map((i) => i.name.toLowerCase()));
  const newIndustries = (seed.industries || []).filter((i) => !existingIndustryNames.has(String(i.name).toLowerCase()));
  newIndustries.forEach((i) => db.industries.push({ id: uid(), name: i.name, responsibleTitle: i.responsibleTitle || "", createdAt: nowIso() }));
  result.industries = { added: newIndustries.length, skipped: (seed.industries || []).filter((i) => existingIndustryNames.has(String(i.name).toLowerCase())).map((i) => i.name) };

  const existingPhraseTexts = new Set(db.phrases.map((p) => p.text.trim().toLowerCase()));
  const newPhrases = (seed.phrases || []).filter((p) => !existingPhraseTexts.has(String(p.text).trim().toLowerCase()));
  newPhrases.forEach((p) => db.phrases.push({ id: uid(), text: p.text, category: p.category || "", subcategory: p.subcategory || "", createdAt: nowIso() }));
  result.phrases = { added: newPhrases.length, skipped: (seed.phrases || []).filter((p) => existingPhraseTexts.has(String(p.text).trim().toLowerCase())).map((p) => p.text) };

  persist().then(() => res.json(result)).catch((e) => res.status(500).json({ error: String(e) }));
});

// "Tee yhteistyötä" -näkymän tuonti: vastaanottaa toiselta
// vaatimusrekisterin käyttäjältä/asennukselta saadun, itsenäisen
// (id-riippumattoman) vaatimuslistan. Puuttuvat kategoriat/alakategoriat/
// omistajat luodaan automaattisesti (nimen perusteella, kirjainkoosta
// riippumatta) — muuten yksikin puuttuva luokka estäisi koko rivin
// tuonnin. Omistajan responsibleTitle ei sisälly vientitiedostoon, joten
// automaattisesti luodulle omistajalle jää täytettävä placeholder-nimike.
// Jo olemassa oleva vaatimus (sama teksti, kirjainkoosta riippumatta)
// ohitetaan, jottei tuonti tuota duplikaatteja. Lisääjä luetaan aina
// tuojan omasta API-avaimesta, ei tiedoston sisällöstä — sama periaate
// kuin POST /api/requirements:ssa.
app.post("/api/collaborate/import", (req, res) => {
  const items = Array.isArray((req.body || {}).items) ? req.body.items : [];
  const createdBy = req.apiKeyInfo ? req.apiKeyInfo.name : "";

  const existingReqTexts = new Set(db.requirements.map((r) => r.text.trim().toLowerCase()));
  const createdCategories = [];
  const createdSubcategories = [];
  const createdIndustries = [];
  const skipped = [];
  let added = 0;

  items.forEach((item) => {
    const text = String((item && item.text) || "").trim();
    const category = String((item && item.category) || "").trim();
    const industry = String((item && item.industry) || "").trim();
    const subcategory = String((item && item.subcategory) || "").trim();
    const type = (item && item.type) || "mandatory";
    const note = String((item && item.note) || "").trim();
    const acceptanceCondition = String((item && item.acceptanceCondition) || "").trim();

    if (!text || !category || !industry) { skipped.push(text || "(tyhjä teksti)"); return; }
    const key = text.toLowerCase();
    if (existingReqTexts.has(key)) { skipped.push(text); return; }

    if (!db.categories.some((c) => c.name.toLowerCase() === category.toLowerCase())) {
      db.categories.push({ id: uid(), name: category, createdAt: nowIso() });
      createdCategories.push(category);
    }
    if (subcategory && !db.subcategories.some((s) => s.name.toLowerCase() === subcategory.toLowerCase())) {
      db.subcategories.push({ id: uid(), name: subcategory, createdAt: nowIso() });
      createdSubcategories.push(subcategory);
    }
    if (!db.industries.some((i) => i.name.toLowerCase() === industry.toLowerCase())) {
      db.industries.push({ id: uid(), name: industry, responsibleTitle: "(täydennä nimike)", createdAt: nowIso() });
      createdIndustries.push(industry);
    }

    db.requirements.push({
      id: uid(),
      text,
      category,
      subcategory,
      industry,
      mandatory: type === "mandatory",
      type,
      note,
      acceptanceCondition,
      createdBy,
      createdAt: nowIso()
    });
    existingReqTexts.add(key);
    added++;
  });

  persist()
    .then(() => res.json({ added, skipped, createdCategories, createdSubcategories, createdIndustries }))
    .catch((e) => res.status(500).json({ error: String(e) }));
});

if (HTTPS_CERT_FILE && HTTPS_KEY_FILE) {
  const options = {
    cert: fs.readFileSync(HTTPS_CERT_FILE),
    key: fs.readFileSync(HTTPS_KEY_FILE)
  };
  https.createServer(options, app).listen(PORT, () => {
    console.log("HARAVA käynnissä (HTTPS): https://localhost:" + PORT);
    console.log("Data tallennetaan tiedostoon: " + DATA_FILE);
  });
} else {
  app.listen(PORT, () => {
    console.log("HARAVA käynnissä: http://localhost:" + PORT);
    console.log("Data tallennetaan tiedostoon: " + DATA_FILE);
  });
}
