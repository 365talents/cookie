'use strict';

const Boom = require('@hapi/boom');
const Bounce = require('@hapi/bounce');
const Hoek = require('@hapi/hoek');
const Validate = require('@hapi/validate');


const internals = {};


module.exports = {
    pkg: require('../package.json'),
    requirements: {
        hapi: '>=18.4.0'
    },
    register: (server, options) => {

        server.auth.scheme('shared-cookie', internals.implementation);
    }
};


internals.schema = Validate.object({

    cookie: Validate.object({
        name: Validate.string().default('sid'),
        ignoreErrors: Validate.valid(true).default(true)
    })
        .unknown()
        .default(),

    keepAlive: Validate.boolean()
        .when('cookie.ttl', { is: Validate.number().min(1), otherwise: Validate.forbidden() })
        .default(false),

    requestDecoratorName: Validate.string().default('cookieAuth'),
    validateFunc: Validate.func()
})
    .required();


internals.CookieAuth = class {

    constructor(request, settings) {

        this.request = request;
        this.settings = settings;
    }
};


internals.implementation = (server, options) => {

    const settings = Validate.attempt(options, internals.schema);
    settings.name = settings.cookie.name;
    delete settings.cookie.name;

    server.state(settings.name, settings.cookie);
    settings.cookie = server.states.cookies[settings.name];

    if (typeof settings.appendNext === 'boolean') {
        settings.appendNext = (settings.appendNext ? 'next' : '');
    }

    if (typeof settings.appendNext === 'object') {
        settings.appendNextRaw = settings.appendNext.raw;
        settings.appendNext = settings.appendNext.name || 'next';
    }

    const decoration = (request) => new internals.CookieAuth(request, settings);
    server.decorate('request', settings.requestDecoratorName, decoration, { apply: true });

    server.ext('onPreAuth', (request, h) => {

        // Used for setting and unsetting state, not for replying to request
        request[settings.requestDecoratorName].h = h;

        return h.continue;
    });

    const scheme = {
        authenticate: async (request, h) => {

            const validate = async () => {

                // Check cookie

                const session = request.state[settings.name];
                if (!session) {
                    return unauthenticated(Boom.unauthorized(null, 'cookie'));
                }

                let credentials = session;

                try {
                    const result = await settings.validateFunc(request, session);

                    Hoek.assert(typeof result === 'object', 'Invalid return from validateFunc');
                    Hoek.assert(Object.prototype.hasOwnProperty.call(result, 'valid'), 'validateFunc must have valid property in return');

                    if (!result.valid) {
                        throw Boom.unauthorized(null, 'cookie');
                    }

                    credentials = result.credentials || credentials;

                    if (settings.keepAlive) {
                        h.state(settings.name, session);
                    }

                    return h.authenticated({ credentials, artifacts: session });
                }
                catch (err) {
                    Bounce.rethrow(err, 'system');

                    let unauthorized = Boom.isBoom(err) && err.typeof === Boom.unauthorized ? err : null;
                    if (!unauthorized) {
                        unauthorized = Boom.unauthorized('Invalid cookie');
                        unauthorized.data = err;
                    }

                    return unauthenticated(unauthorized, { credentials, artifacts: session });
                }
            };

            const unauthenticated = (err) => {
                return h.response(err);
            };

            return await validate();
        }
    };

    return scheme;
};
