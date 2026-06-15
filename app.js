const express = require('express');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const app = express();
const PORT = process.env.PORT || 8000;

const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'JWT Labs',
            version: '1.0.0',
            description: '',
        },
        servers: [
            {
                url: 'http://localhost:8000',
            },
        ],
        components: {
            securitySchemes: {
                ApiKeyAuth: {
                    type: 'apiKey',
                    in: 'header',
                    name: 'Authorization',
                    description: 'JWT token (paste the token directly, without Bearer prefix)',
                },
            },
        },
    },
    apis: ['./controllers/*.js'],
};

// Injected into Swagger UI page as inline JS.
// Swagger UI 3.x silently drops 'Authorization' header parameters per OpenAPI 3.0 spec.
// This interceptor reads the value typed into the Authorization input field and
// re-injects it as an actual request header before every fetch call.
const customJsStr = `
(function waitForUI() {
  if (typeof window.ui === 'undefined') {
    setTimeout(waitForUI, 300);
    return;
  }
  var cfg = window.ui.getConfigs();
  var prev = cfg.requestInterceptor || function(r){ return r; };
  cfg.requestInterceptor = function(request) {
    request = prev(request);
    if (request.headers && request.headers['Authorization']) return request;
    // Find Authorization input typed by user in the parameter form
    var rows = document.querySelectorAll('.parameters-col_description, .parameter__name');
    var authInput = null;
    document.querySelectorAll('tr.parameters').forEach(function(row) {
      var nameEl = row.querySelector('.parameter__name');
      if (nameEl && nameEl.textContent.trim().replace(/\\s+/g,'').startsWith('Authorization')) {
        authInput = row.querySelector('input[type=text], textarea');
      }
    });
    if (!authInput) {
      // fallback: any text input whose placeholder says Authorization
      authInput = document.querySelector('input[placeholder="Authorization"]');
    }
    if (!authInput) {
      // fallback: find by aria-label
      authInput = document.querySelector('input[aria-label="Authorization"]');
    }
    if (authInput && authInput.value && authInput.value.trim()) {
      if (!request.headers) request.headers = {};
      request.headers['Authorization'] = authInput.value.trim();
    }
    return request;
  };
  console.log('[JWT Lab] Authorization interceptor active.');
})();
`;

const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use('/swagger', swaggerUi.serve, swaggerUi.setup(swaggerDocs, { customJsStr }));

app.get('/', (req,res) => {
    return res.redirect('/swagger')
})

app.use("/", express.static(__dirname + '/public'));

app.use('/weak-secret', require('./controllers/weak-secret'));
app.use('/none-attack', require('./controllers/none-attack'));
app.use('/kid-injection', require('./controllers/kid-injection'));
app.use('/jku-injection', require('./controllers/jku-injection'));
app.use('/algorithm-confusion', require('./controllers/algorithm-confusion'));

app.listen(PORT, () => {
    console.log(`Listening on http://localhost:${PORT}/`);
});
