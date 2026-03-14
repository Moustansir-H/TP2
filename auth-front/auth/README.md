# Auth Front TP2 (JavaFX FXML)

Client JavaFX FXML pour le TP2:
- inscription
- login
- validation email/mot de passe côté client
- confirmation du mot de passe
- indicateur de force (rouge / orange / vert)
- appel backend Spring Boot (`/api/auth/register`, `/api/auth/login`)

## Pré-requis

- Java 17+
- Maven (ou `mvnw.cmd`)
- Backend Spring Boot lancé (par défaut `http://localhost:8080`)

## Lancer le backend

Depuis `TP2/auth`:

```powershell
cd C:\Users\hassa\IdeaProjects\TP2\auth
.\mvnw.cmd spring-boot:run
```

## Lancer le front

Depuis `TP2/auth-front/auth`:

```powershell
cd C:\Users\hassa\IdeaProjects\TP2\auth-front\auth
.\mvnw.cmd javafx:run
```

## Vérifier compilation/tests front

```powershell
cd C:\Users\hassa\IdeaProjects\TP2\auth-front\auth
.\mvnw.cmd test
```

## Règle TP2 utilisée côté client

Mot de passe valide si:
- au moins 12 caractères
- au moins 1 majuscule
- au moins 1 minuscule
- au moins 1 chiffre
- au moins 1 caractère spécial

## Fichiers principaux

- `src/main/resources/com/example/auth/auth-view.fxml`
- `src/main/java/com/example/auth/controller/AuthController.java`
- `src/main/java/com/example/auth/service/AuthApiClient.java`
- `src/main/java/com/example/auth/service/ClientValidationService.java`
- `src/main/java/com/example/auth/HelloApplication.java`

