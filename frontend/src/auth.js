import {
  CognitoUserPool,
  CognitoUser,
  AuthenticationDetails,
} from 'amazon-cognito-identity-js';
import { config } from './config';

const userPool = new CognitoUserPool({
  UserPoolId: config.userPoolId,
  ClientId: config.clientId,
});

// In-memory reference to the authenticated CognitoUser object.
// This is the KEY to making getSession() work reliably.
let _cognitoUser = null;

export function isAuthenticated() {
  return !!(_cognitoUser || userPool.getCurrentUser());
}

export function getToken() {
  return new Promise((resolve, reject) => {
    // Use in-memory reference first, fall back to localStorage reconstruction
    const user = _cognitoUser || userPool.getCurrentUser();
    if (!user) return reject(new Error('No user found (not signed in)'));

    // getSession() auto-refreshes expired access tokens using the refresh token
    user.getSession((err, session) => {
      if (err) {
        _cognitoUser = null;
        return reject(new Error('getSession failed: ' + (err.message || JSON.stringify(err))));
      }
      if (!session || !session.isValid()) {
        _cognitoUser = null;
        return reject(new Error('Session invalid'));
      }
      _cognitoUser = user; // keep reference fresh
      resolve(session.getIdToken().getJwtToken());
    });
  });
}

export function signIn(email, password) {
  return new Promise((resolve, reject) => {
    const user = new CognitoUser({ Username: email, Pool: userPool });
    const auth = new AuthenticationDetails({ Username: email, Password: password });
    user.authenticateUser(auth, {
      onSuccess: (session) => {
        _cognitoUser = user; // save the SAME object that authenticated
        resolve({ success: true });
      },
      onFailure: (err) => {
        if (err.code === 'PasswordResetRequiredException') {
          resolve({ passwordResetRequired: true, email });
        } else {
          reject(err);
        }
      },
      newPasswordRequired: () => {
        resolve({ newPasswordRequired: true, cognitoUser: user });
      },
    });
  });
}

export function completeNewPassword(cognitoUser, newPassword) {
  return new Promise((resolve, reject) => {
    cognitoUser.completeNewPasswordChallenge(newPassword, {}, {
      onSuccess: (session) => {
        _cognitoUser = cognitoUser; // save reference after password set
        resolve();
      },
      onFailure: reject,
    });
  });
}

export function confirmResetPassword(email, code, newPassword) {
  return new Promise((resolve, reject) => {
    const user = new CognitoUser({ Username: email, Pool: userPool });
    user.confirmPassword(code, newPassword, {
      onSuccess: () => resolve(),
      onFailure: reject,
    });
  });
}

export function signOut() {
  const user = _cognitoUser || userPool.getCurrentUser();
  if (user) user.signOut();
  _cognitoUser = null;
}

export function getUserProfile() {
  return new Promise((resolve, reject) => {
    const user = _cognitoUser || userPool.getCurrentUser();
    if (!user) return reject(new Error('Not signed in'));
    user.getSession((err, session) => {
      if (err || !session?.isValid()) return reject(err || new Error('Invalid session'));
      const payload = session.getIdToken().decodePayload();
      resolve({ username: payload['cognito:username'] || payload['sub'], email: payload['email'] });
    });
  });
}

export function changePassword(oldPassword, newPassword) {
  return new Promise((resolve, reject) => {
    const user = _cognitoUser || userPool.getCurrentUser();
    if (!user) return reject(new Error('Not signed in'));
    user.getSession((err, session) => {
      if (err || !session?.isValid()) return reject(err || new Error('Invalid session'));
      user.changePassword(oldPassword, newPassword, (err, result) => {
        if (err) return reject(err);
        resolve(result);
      });
    });
  });
}
