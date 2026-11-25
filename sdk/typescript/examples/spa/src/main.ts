// Minimal SPA: redirect login or in-app login with OTP, profile with live
// updates, nickname editing and logout. Serve this folder over http(s) and
// register its URL as the client's redirect URI.

import { createMoonSso, MoonSsoError, OtpRequiredError, type Profile } from '@moon-sso/browser';

const ISSUER = 'https://sso.moonl.cloud';
const CLIENT_ID = 'your-spa-client-id';
const REDIRECT_URI = `${location.origin}${location.pathname}`;

function el<T extends HTMLElement>(id: string): T {
  const e = document.getElementById(id);
  if (!e) {
    throw new Error(`#${id} missing`);
  }
  return e as T;
}

const status = el<HTMLParagraphElement>('status');
const signedOut = el<HTMLElement>('signed-out');
const signedIn = el<HTMLElement>('signed-in');
const loginForm = el<HTMLFormElement>('login-form');
const otpForm = el<HTMLFormElement>('otp-form');
const nicknameForm = el<HTMLFormElement>('nickname-form');

const sso = await createMoonSso({
  issuer: ISSUER,
  clientId: CLIENT_ID,
  redirectUri: REDIRECT_URI,
  postLogoutRedirectUri: REDIRECT_URI,
  scope: 'openid profile offline_access profile:write',
});

function showProfile(p: Profile): void {
  el('name').textContent = p.name;
  el('username').textContent = p.preferred_username;
  (nicknameForm.elements.namedItem('nickname') as HTMLInputElement).value = p.nickname;
}

async function render(): Promise<void> {
  signedIn.hidden = !sso.isAuthenticated;
  signedOut.hidden = sso.isAuthenticated;
  status.textContent = sso.isAuthenticated ? '' : 'Not signed in';
  if (sso.isAuthenticated) {
    showProfile(await sso.getMe());
    await sso.startEvents();
  }
}

sso.on('profileChanged', showProfile);
sso.on('sessionExpired', () => {
  status.textContent = 'Your session ended. Please sign in again.';
  void render();
});
sso.on('logout', () => void render());

function describe(e: unknown): string {
  if (e instanceof MoonSsoError) {
    return e.error_description ?? e.error;
  }
  return 'Something went wrong';
}

el<HTMLButtonElement>('login-redirect').addEventListener('click', () => {
  void sso.login({ returnTo: location.pathname });
});

let authSession: string | undefined;
loginForm.addEventListener('submit', (ev) => {
  ev.preventDefault();
  const data = new FormData(loginForm);
  sso
    .signIn(String(data.get('username')), String(data.get('password')))
    .then(render)
    .catch((e: unknown) => {
      if (e instanceof OtpRequiredError) {
        authSession = e.authSession;
        otpForm.hidden = false;
        status.textContent = 'Enter the code from your authenticator app';
        return;
      }
      status.textContent = describe(e);
    });
});

otpForm.addEventListener('submit', (ev) => {
  ev.preventDefault();
  if (!authSession) {
    return;
  }
  const otp = String(new FormData(otpForm).get('otp'));
  sso
    .verifyOtp(authSession, otp)
    .then(() => {
      otpForm.hidden = true;
      return render();
    })
    .catch((e: unknown) => {
      status.textContent = e instanceof OtpRequiredError ? 'Wrong code, try again' : describe(e);
    });
});

nicknameForm.addEventListener('submit', (ev) => {
  ev.preventDefault();
  const nickname = String(new FormData(nicknameForm).get('nickname'));
  sso.updateProfile({ displayName: nickname }).catch((e: unknown) => {
    status.textContent = describe(e);
  });
});

el<HTMLButtonElement>('logout').addEventListener('click', () => {
  void sso.logout({ endSession: true });
});

try {
  if (sso.isRedirectCallback()) {
    const { returnTo } = await sso.handleRedirectCallback();
    if (returnTo && returnTo !== location.pathname) {
      history.replaceState(null, '', returnTo);
    }
  }
} catch (e) {
  status.textContent = describe(e);
}
await render();
