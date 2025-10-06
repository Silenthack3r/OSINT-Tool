// Simple CSRF helper: reads meta[name="csrf-token"] and adds X-CSRF-Token header to fetch calls
(function(){
  try {
    const meta = document.querySelector('meta[name="csrf-token"]');
    const token = meta ? meta.content : '';
    if(!token) return; // nothing to do
    const _fetch = window.fetch;
    window.fetch = function(resource, init){
      init = init || {};
      init.headers = init.headers || {};
      if(!init.headers['X-CSRF-Token']){
        init.headers['X-CSRF-Token'] = token;
      }
      return _fetch(resource, init);
    };
    // XHR fallback
    const _open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, async){
      this._csrf_token = token;
      return _open.apply(this, arguments);
    };
    const _send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body){
      try{
        if(this._csrf_token && !this.getRequestHeader('X-CSRF-Token')){
          this.setRequestHeader('X-CSRF-Token', this._csrf_token);
        }
      }catch(e){/* some browsers disallow getRequestHeader before open/send */}
      return _send.apply(this, arguments);
    };
  }catch(e){console.error('csrf helper failed', e)}
})();
