# HARAVA

HARAVA (Hankintojen rakenteelliset vaatimukset) on KOKEELLINEN pieni jaettu 
sovellus vaatimuskirjaston, kategorioiden, alakategorioiden, omistajien, yritysten,
fraasien ja listojen hallintaan.

Useampi käyttäjä voi käyttää samaa palvelinta samanaikaisesti selaimella —
data on kaikille yhteinen ja tallentuu palvelimelle tiedostoon `data/db.json`.

## Vaatimukset

- Node.js 18 tai uudempi (`node -v` tarkistaa version)
- Verkkoyhteys asennusvaiheessa pakettien lataamiseen (`npm install`), ei
  käytön aikana

## Asennus ja käynnistys

```bash
cd <hakemisto>
npm install
npm start
```

Sovellus käynnistyy oletuksena porttiin 3000. Muut käyttäjät samassa
verkossa pääsevät siihen osoitteesta `http://<palvelimen-ip>:3000`.

Eri portin voi asettaa ympäristömuuttujalla:

```bash
PORT=8080 npm start
```

## API-avainsuojaus (valinnainen)

REST-rajapinta (`/api/*`) voidaan suojata API-avaimilla. Kopioi
`.env.example` nimelle `.env` ja aseta `API_KEYS`-muuttuja muotoon
`Nimi:avain:viimeinenVoimassaolopäivä:oletusOmistaja:oletusYritys:käyttöoikeus`
(useampi avain pilkulla eroteltuna; kolme viimeistä osaa valinnaisia),
esim.:

```
API_KEYS=Toimisto:abc123def456:2026-12-31:Tietotekniikka:Esimerkki Oy
```

Jos `.env`-tiedostoa tai `API_KEYS`-muuttujaa ei ole, rajapinta toimii
ilman autentikointia (oletus). Kun avaimet on asetettu, palvelin on
käynnistettävä uudelleen, ja käyttöliittymä kysyy avaimen käyttäjältä
kerran ja muistaa sen selaimessa.

Oletusomistaja ja -yritys ovat valinnaisia mukavuusominaisuuksia: ne
esitäyttävät Kirjasto-näkymän omistaja-suodattimen/uuden vaatimuksen
omistajan sekä uuden listan yrityksen tällä avaimella kirjautuneelle
käyttäjälle, mutta eivät rajoita mitä käyttäjä voi valita tai nähdä.

Käyttöoikeus voi olla `readonly`, jolloin avaimella saa vain katsella
tietoja ja tulostaa listoja — kaikki muut kuin GET-pyynnöt hylätään
403:lla. Jätä pois täysille oikeuksille. Esimerkki vain luku -avaimesta
(oletusomistaja/-yritys jätetty tyhjäksi, kentät silti pidettävä paikallaan
kaksoispistein):

```
API_KEYS=Katselija:xyz789:2026-06-30:::readonly
```

## Data ja varmuuskopiointi

Kaikki data (vaatimuskirjasto, kategoriat, listat) tallentuu yhteen
tiedostoon: `data/db.json`. Varmuuskopiointi = tämän tiedoston kopiointi
talteen esimerkiksi kerran päivässä (cron-ajastus). Palautus = tiedoston
korvaaminen ja palvelimen uudelleenkäynnistys.

## Käyttö yhteisessä verkossa / reverse proxyn takana

Jos sovellus halutaan tarjota tutulla verkkotunnuksella ja HTTPS:llä,
laita sen eteen esim. nginx tai Apache reverse proxy osoittamaan
palvelimen porttiin (oletus 3000). Sovellus itsessään ei vaadi HTTPS:ää
sisäverkossa, mutta se on suositeltavaa, jos liikenne kulkee laajemman
verkon yli.

## Rajoitukset

- Sovelluksessa ei ole käyttäjätunnistusta / kirjautumista. Valinnainen
  API-avainsuojaus (ks. yllä) rajaa pääsyä rajapintaan, mutta ei erottele
  käyttäjiä toisistaan — kaikki avaimen tietävät näkevät ja voivat
  muokata samaa dataa. Jos tarvitaan käyttäjäkohtaista kirjautumista,
  palvelimen eteen tarvitaan esim. reverse proxyn tarjoama kirjautuminen.
- Muutokset muilta käyttäjiltä päivittyvät näkymään automaattisesti
  muutaman sekunnin viiveellä (pollaus), ei reaaliaikaisesti.
