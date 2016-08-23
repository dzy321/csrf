
exports = module.exports = function (app, opts) {
  if (isApp(app)) {
    opts = opts || {}
  } else {
    opts = app || {}
    app = null
  }

  var tokens = require('csrf')(opts)
  var middleware = opts.middleware || exports.middleware

  if (app) {
    define(app)
    return app
  }

  return function* csrf(next) {
    define(this)
    yield middleware.call(this, next)
  }

  function define(ctx) {
    var context = ctx.context || ctx
    var response = ctx.response
    var request = ctx.request

    /*
     * Lazily creates a CSRF token.
     * Creates one per request.
     *
     * @api public
     */

    context.getCsrf = function () {
      var that = this;
      return new Promise(function (resolve) {
        if (that._csrf) {
          resolve(that._csrf)
          return
        }
        if (!that.session) {
          resolve(null)
          return
        }
        var secret = that.session.secret
          || (that.session.secret = tokens.secretSync())
        resolve(that._csrf = tokens.create(secret))
      });
    }

    response.getCsrf = function () {
      return this.ctx.getCsrf()
    }

    /**
     * Asserts that a CSRF token exists and is valid.
     * Throws a 403 error otherwise.
     * var body = yield this.request.json()
     * try {
     *   this.assertCSRF(body)
     * } catch (err) {
     *   this.status = 403
     *   this.body = {
     *     message: 'invalid CSRF token'
     *   }
     * }
     *
     * @param {Object} body
     * @return {Context} this
     * @api public
     **/

    context.assertCSRF =
      context.assertCsrf = function (body) {
        // no session
        var that = this;
        return new Promise(function (resolve) {
          var secret = that.session.secret
          if (!secret) that.throw(403, 'secret is missing')

          var token = (body && body._csrf)
            || (!opts.disableQuery && that.query && that.query._csrf)
            || (that.get('x-csrf-token'))
            || (that.get('x-xsrf-token'))
            || body
          if (!token) that.throw(403, 'token is missing')
          if (!tokens.verify(secret, token)) that.throw(403, 'invalid csrf token')

          resolve(that)
        });
      }

    request.assertCSRF =
      request.assertCsrf = function (body) {
        return this.ctx.assertCsrf(body)
      }
  }
}

/**
 * a middleware to handle csrf check
 *
 * @api public
 */
exports.middleware = function* (next) {
  // ignore get, head, options
  if (this.method === 'GET'
    || this.method === 'HEAD'
    || this.method === 'OPTIONS') {
    return yield next
  }

  // bodyparser middlewares maybe store body in request.body
  // or you can just set csrf token header
  yield this.assertCSRF(this.request.body)

  yield next
}

/**
 * check if is koa app instance
 *
 * @api private
 */
function isApp(app) {
  return app && app.context && app.response && app.request
}
