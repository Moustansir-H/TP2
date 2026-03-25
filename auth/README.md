# TP3 - Authentification forte (HMAC + nonce + timestamp)

Ce projet implemente un protocole de preuve d'identite ou le mot de passe n'est jamais envoye au serveur pendant le login.

## Objectif pedagogique

- Passer de "j'envoie mon mot de passe" a "je prouve que je connais un secret".
- Introduire HMAC, nonce, timestamp, anti-rejeu et comparaison en temps constant.
- Conserver SonarCloud avec une couverture cible >= 80%.

## Important

Ce mecanisme est pedagogique.

- En industrie, on evite de stocker un mot de passe reversible.
- On prefere un hash adaptatif non reversible (Argon2, bcrypt, scrypt, PBKDF2 selon contexte).
- Ici, le stockage chiffre reversible est accepte uniquement pour illustrer le protocole signe de TP3.

## Endpoints

### 1) Inscription

`POST /api/auth/register`

Payload:

```json
{
  "email": "user@example.com",
  "password": "Password@123"
}
```

### 2) Login par preuve HMAC

`POST /api/auth/login`

Payload:

```json
{
  "email": "user@example.com",
  "nonce": "7a4a34f9-2c88-4f4e-b57a-0f5a6c4f9d1f",
  "timestamp": 1770000000,
  "hmac": "BASE64_HMAC_SHA256"
}
```

Message signe cote client:

`email + ":" + nonce + ":" + timestamp`

HMAC cote client:

`HMAC_SHA256(key=password, data=message)` encode en Base64.

Reponse OK:

```json
{
  "message": "Connexion reussie",
  "email": "user@example.com",
  "accessToken": "...",
  "expiresAt": "2026-03-22T12:34:56"
}
```

### 3) Endpoint protege

`GET /api/me`

Header:

`Authorization: Bearer <accessToken>`

## Regles TP3 implementees

- Fenetre timestamp acceptee: +/- 60 secondes.
- Nonce anti-rejeu stocke en base avec TTL 120 secondes.
- Reutilisation d'un nonce pour le meme utilisateur: rejetee.
- Token d'acces emis pour 15 minutes.
- Comparaison HMAC en temps constant (`MessageDigest.isEqual`).

## Configuration

Dans `src/main/resources/application.yaml`:

- `auth.security.server-master-key`
- `auth.security.timestamp-window-seconds`
- `auth.security.nonce-ttl-seconds`
- `auth.security.token-ttl-seconds`

## Tests

Les tests couvrent notamment:

- login OK HMAC valide
- login KO HMAC invalide
- timestamp expire/futur
- nonce rejoue
- token OK sur `/api/me`
- acces `/api/me` sans token KO
