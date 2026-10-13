/* auth.js
   Accounts live on the server (SQLite). The browser only keeps a login cookie
   that JavaScript cannot read. Auth.user() stays synchronous: it returns the
   user loaded by Auth.ready, so wait for Auth.ready before using it. */
const Auth = (() => {
  let current = null;

  async function call(method, url, body){
    let res;
    try{
      res = await fetch(url, {
        method,
        credentials: 'same-origin',
        headers: body ? {'Content-Type': 'application/json'} : undefined,
        body: body ? JSON.stringify(body) : undefined
      });
    }catch(e){
      throw new Error('Could not reach the server. Make sure it is running, and open the site from its address (for example http://localhost:3000).');
    }
    let data = {};
    try{ data = await res.json(); }catch(e){}
    if (!res.ok){
      const err = new Error(data.error || 'Something went wrong. Please try again.');
      err.status = res.status;
      throw err;
    }
    return data;
  }

  const cleanEmail = e => String(e || '').trim().toLowerCase();
  const isEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);

  /* ask the server who is logged in (never throws) */
  async function refresh(){
    try{ current = (await call('GET', '/api/me')).user || null; }
    catch(e){ current = null; }
    return current;
  }
  const ready = refresh();

  async function register({name, email, password}){
    name = String(name || '').trim();
    email = cleanEmail(email);
    if (name.length < 2)       throw new Error('Enter your name.');
    if (!isEmail(email))       throw new Error('Enter a valid email address.');
    if (String(password || '').length < 8) throw new Error('Use a password with at least 8 characters.');
    current = (await call('POST', '/api/register', {name, email, password})).user;
    return current;
  }

  async function login({email, password}){
    current = (await call('POST', '/api/login', {email: cleanEmail(email), password: String(password || '')})).user;
    return current;
  }

  async function logout(){
    try{ await call('POST', '/api/logout'); }catch(e){}
    current = null;
  }

  function user(){ return current; }

  /* where to go after logging in; only same-site pages are allowed */
  function next(){
    const n = new URLSearchParams(location.search).get('next') || '';
    return /^[\w.-]+\.html(#[\w-]*)?$/.test(n) ? n : 'index.html#explore';
  }

  /* wires every "Show" button next to a password field */
  function wirePasswordToggles(){
    document.querySelectorAll('.show').forEach(btn => {
      btn.addEventListener('click', () => {
        const input = btn.parentElement.querySelector('input');
        const showing = input.type === 'text';
        input.type = showing ? 'password' : 'text';
        btn.textContent = showing ? 'Show' : 'Hide';
        btn.setAttribute('aria-pressed', String(!showing));
      });
    });
  }

  return {ready, register, login, logout, user, next, wirePasswordToggles, call};
})();