
// Swagger UI request interceptor
// Waits for Swagger UI to initialize, then overrides requestInterceptor
// to ensure the Authorization header parameter value is actually sent.
(function() {
  function waitForSwagger() {
    if (typeof window.ui === 'undefined') {
      setTimeout(waitForSwagger, 200);
      return;
    }

    window.ui.getConfigs().requestInterceptor = function(request) {
      // If Authorization was typed into the parameter field, swagger stores it
      // in ui.getState() but drops it from the request due to OpenAPI 3.0 rules.
      // We retrieve it from the system and re-add it.
      try {
        var state = window.ui.getState();
        // Walk through all parameter values to find Authorization header params
        var oas3 = state.getIn(['oas3', 'requestData']);
        if (oas3) {
          oas3.forEach(function(pathData) {
            if (pathData && pathData.get) {
              var params = pathData.get('parameters');
              if (params) {
                var authVal = params.get('Authorization');
                if (authVal && !request.headers['Authorization']) {
                  request.headers['Authorization'] = authVal;
                }
              }
            }
          });
        }
      } catch(e) {
        // silently ignore
      }
      return request;
    };
    console.log('[JWT Lab] Request interceptor installed: Authorization header will be sent.');
  }
  waitForSwagger();
})();
