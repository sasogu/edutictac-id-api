# EduTicTac ID API

API REST mínima per a credencials pseudònimes d'alumnat.

El servei permet generar codis públics i PINs privats perquè l'alumnat puga
mantindre rànquings, preferits o progrés entre aplicacions EduTicTac sense
guardar noms, correus, telèfons, NIA ni identificadors institucionals.

Usa `edutictac-community` com a nucli comú per a SQLite, rate limit i cookies
firmades. La lògica sensible d'identitat, PINs, grups opacs, sessions
d'alumnat i puntuacions pseudònimes continua en aquest servei.

## Principis

- El codi públic (`K7P`) és el que apareix en rànquings.
- El PIN només es mostra quan es genera o es regenera.
- El PIN es guarda amb hash PBKDF2, mai en text pla.
- Els codis nous es generen únics globalment perquè l'alumnat només haja
  d'introduir codi públic + PIN.
- El grup guardat al servidor és un codi opac (`G7F4K2`), no el nom real del
  centre, curs o aula.
- El professorat gestiona la correspondència real fora de la plataforma; el
  grup queda com a dada interna per a l'organització docent.

## Endpoints principals

- `GET /api/health`
- `POST /api/teacher/login`
- `POST /api/groups`
- `POST /api/identities/batch`
- `POST /api/auth/student`
- `GET /api/auth/me`
- `POST /api/auth/logout`
- `POST /api/identities/{id}/regenerate-pin`
- `POST /api/identities/{id}/revoke`
- `POST /api/teacher/activity-assignments`
- `GET /api/teacher/activity-assignments`
- `POST /api/scores` (`assignment_id` opcional quan el resultat pertany a una activitat proposada pel professorat)
- `GET /api/rankings` (només alumnat amb sessió o professorat autenticat)
- `GET /api/teacher/stats.csv`
- `GET /api/teacher/identities/by-code/{public_code}`
- `GET /api/groups/{group_id}/cards`
- `GET /api/groups/{group_id}/csv`
- `POST /api/apps/{app_id}/roster`

El roster per aplicació retorna només codis pseudònims i identificadors tècnics
derivats (`eduhoot-k7p`, `banc-recursos-k7p`). No publica PINs ni dades reals
de l'alumnat.

## Execució local

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
EDUTICTAC_ID_DB=/tmp/edutictac-id.db \
EDUTICTAC_ID_SECRET=dev-secret \
EDUTICTAC_ID_TEACHER_TOKEN=dev-teacher \
EDUTICTAC_ID_COOKIE_SECURE=0 \
uvicorn main:app --host 127.0.0.1 --port 8005
```

Tests:

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Nucli comú

Dependència estable actual:

```txt
edutictac-community @ git+https://git.edutictac.es/Edutictac/edutictac-community.git@v0.1.1
```

Components reutilitzats:

- `edutictac_community.db.connect` per a SQLite amb WAL. El servei afegeix
  localment `PRAGMA foreign_keys=ON`.
- `edutictac_community.ratelimit.RateLimiter` per a intents d'accés.
- `edutictac_community.session.SignedSession` per a cookies HMAC, mantenint els
  wrappers interns `make_cookie` i `parse_cookie`.

## Exemple

```bash
curl -H 'Authorization: Bearer dev-teacher' \
  -H 'Content-Type: application/json' \
  -d '{"count":25,"pin_length":4}' \
  http://127.0.0.1:8005/api/identities/batch
```

La resposta inclou un codi de grup opac per al professorat i els PINs només en
eixe moment. Després no es poden recuperar: cal regenerar-los. L'alumnat no
necessita el codi de grup per iniciar sessió; amb el seu codi públic i PIN és
suficient. Si el professorat necessita saber que `G7F4K2` equival a `3ESO-A`,
ho manté fora de la plataforma.

Els rànquings no són públics oberts: només els pot consultar alumnat amb sessió
EduTicTac ID o professorat autenticat. El professorat disposa també d'una
exportació CSV d'estadístiques per grup amb codi pseudònim, activitat, intents,
millor puntuació i última data.

Per separar identitat compartida i visibilitat docent, les activitats proposades
pel professorat es representen amb `activity_assignments`: una assignació uneix
`app_id`, `activity_id`, `group_id` i `created_by_teacher_id`. Quan una puntuació
prové d'una activitat proposada, `POST /api/scores` pot enviar `assignment_id`;
el servei valida que l'assignació correspon al mateix recurs base i al grup de
l'alumne. Això permet que dos docents usen el mateix recurs sense barrejar els
resultats als futurs panells.

Les aplicacions EduTicTac poden demanar el roster pseudònim del seu grup amb
`POST /api/apps/{app_id}/roster`. Aquest contracte serveix per connectar
EduHoot, Banc de recursos o altres eines pròpies sense crear dependències amb
plataformes descartades o externes.

## Configuració

| Variable | Ús |
|---|---|
| `EDUTICTAC_ID_DB` | Ruta SQLite |
| `EDUTICTAC_ID_SECRET` | Secret per signar cookies |
| `EDUTICTAC_ID_TEACHER_TOKEN` | Token provisional per al professorat fins a OIDC |
| `EDUTICTAC_ID_COOKIE_DOMAIN` | Domini compartit opcional, per exemple `.edutictac.es` |
| `EDUTICTAC_ID_COOKIE_SECURE` | `1` per defecte. Usa `0` només en desenvolupament local |

## Desplegament actual

En la instància EduTicTac el servei està instal·lat en `/opt/edutictac-id-api`,
amb systemd `edutictac-id-api.service`, SQLite en
`/opt/edutictac-id-api/data/id.db` i escoltant només en `127.0.0.1:8005`.
No té vhost públic propi: el consumeixen altres backends, com `recursos-api`,
per xarxa local del servidor.

## Mode Centres Educatius

Aquest servei està dissenyat per minimitzar el tractament de dades personals,
no per prometre anonimat absolut. Si el professorat conserva fora de la
plataforma una taula que relaciona `K7P` amb una alumna concreta, cal tractar
el flux amb prudència jurídica.

Regles de desplegament recomanades:

- No guardar noms reals de centres, grups, cursos ni alumnat.
- Publicar només codis pseudònims i puntuacions estrictament necessàries.
- No afegir analítica de tercers, publicitat, fonts externes ni trackers.
- Mantindre logs tècnics amb retenció curta i sense PINs.
- Documentar responsable, finalitats, categories de dades, allotjament,
  conservació, destinataris i mesures de seguretat en una pàgina pública.

## Llicència

MIT.
