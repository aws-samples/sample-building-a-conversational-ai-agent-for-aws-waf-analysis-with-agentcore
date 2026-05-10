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

export function getCurrentUser() {
  return userPool.getCurrentUser();
}

export function getToken() {
  return new Promise((resolve, reject) => {
    const user = getCurrentUser();
    if (!user) return reject(new Error('Not signed in'));
    user.getSession((err, session) => {
      if (err) return reject(err);
      resolve(session.getAccessToken().getJwtToken());
    });
  });
}

export function signIn(email, password) {
  return new Promise((resolve, reject) => {
    const user = new CognitoUser({ Username: email, Pool: userPool });
    const auth = new AuthenticationDetails({ Username: email, Password: password });
    user.authenticateUser(auth, {
      onSuccess: (session) => resolve({ token: session.getAccessToken().getJwtToken() }),
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

export function confirmResetPassword(email, code, newPassword) {
  return new Promise((resolve, reject) => {
    const user = new CognitoUser({ Username: email, Pool: userPool });
    user.confirmPassword(code, newPassword, {
      onSuccess: () => resolve(),
      onFailure: reject,
    });
  });
}

export function completeNewPassword(cognitoUser, newPassword) {
  return new Promise((resolve, reject) => {
    cognitoUser.completeNewPasswordChallenge(newPassword, {}, {
      onSuccess: (session) => resolve(session.getAccessToken().getJwtToken()),
      onFailure: reject,
    });
  });
}

export function signOut() {
  const user = getCurrentUser();
  if (user) user.signOut();
}
