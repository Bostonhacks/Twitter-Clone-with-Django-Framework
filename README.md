# Authenticator

This server authenticates users with BU Kerberos and returns a Firebase token that can be used with our various Firebase applications (main website, interview tool, etc). Authenticator is built with [Express.js](https://expressjs.com/), [Passport.js](http://www.passportjs.org/), and [Firebase](https://firebase.google.com/).

## How it works

When a user lands on `https://upe-authenticator.herokuapp.com/`, first the `referrer` header is saved into session storage. Next, the server checks whether the request is authenticated with Passport, i.e. has the user authenticated through Kerberos this session. If the user is authenticated, a Firebase token is generated using the `req.user` object and the user is redirected back where they came from (using the saved `referrer` header in session storage) with the token as a query param. If the user isn't authenticated, the user is redirected to BU Kerberos, after which the same token generation and redirection will occur.

## How to connect

To use this authentication server in a new Firebase project, first make sure that project is using the "UPE Master" Firebase instance. Then create a login page that checks for the existence of the `token` query param. If the param exists, login with it, otherwise redirect the user to Authenticator (`https://upe-authenticator.herokuapp.com/`).

```
const Login = ({ firebase }) => {
  useEffect(() => {
    if (firebase) {
      const urlParams = new URLSearchParams(window.location.search);
      const token = urlParams.get("token");
      if (token) {
        firebase
          .doSignInWithToken(token)
          .then(() => navigate("/"))
          .catch(console.error);
      } else {
        window.location.href = "https://upe-authenticator.herokuapp.com/";
      }
    }
  }, [firebase]);

  return (
    <div>
      <h1>Authenticating...</h1>
    </div>
  );
};
```

For a full example of an application using Authenticator, check out [Inquisitor](https://github.com/BUUPE/Inquisitor).

## Testing Locally

Clone the repo, copy `.env.example` to `.env` and fill out appropriately (for more info on how to configure the certificates, check out [BU-SSO-Example](https://github.com/Bostonhacks/BU-SSO-Example)), then run:

```
yarn install
yarn start
```
