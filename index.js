const R = require('ramda')
const Either = require('data.either')
const jwt = require('jsonwebtoken')
const cookie = require('cookie')

const fn_utils = require('@cr-ste-justine/functional-utils')
const either_utils = fn_utils.either
const monad_utils = fn_utils.monad

class TokenUndefinedError extends Error {
    constructor(message) {
        super(message)
        this.name = this.constructor.name
        Error.captureStackTrace(this, this.constructor)
    }
}

const generate_token_undefined_err = () => new TokenUndefinedError("Token undefined")

class TokenDecodeError extends Error {
    constructor(message) {
        super(message)
        this.name = this.constructor.name
        Error.captureStackTrace(this, this.constructor)
    }
}

const generate_token_decode_err = () => new TokenDecodeError("Token is not decodable")

class TokenVersionError extends Error {
    constructor(message) {
        super(message)
        this.name = this.constructor.name
        Error.captureStackTrace(this, this.constructor)
    }
}

class TokenExpiryError extends Error {
    constructor(message) {
        super(message)
        this.name = this.constructor.name
        Error.captureStackTrace(this, this.constructor)
    }
}

/*
  Given the encrypted token, tries to decrypted it.
  It returns either the decrypted token (if successful) or an error (on failure)
  Either way, the result is wrapped in an Either monad
  Signature:
  (key, encrypted_token) => Either(decrypted_token | TokenDecodeErrorError)
*/
const decode_token = R.curry(R.compose(
    either_utils.if_nil_else(
        generate_token_decode_err,
        R.identity
    ),
    (key, token) => jwt.decode(token, key)
))

/*
  Given the decrypted token, check that the version of the token matches the expected version
  The check passes if the version is undefined (it assumes in that case that there are no version checks).
  The function returns the token if the check is successful, else it returns an error.
  The result is wrapped in an Either monad.
  Signature:
  (version_getter_fn, decrypted_token) => Either(decrypted_token | TokenVersionError)
*/
const check_token_version = R.curry((versionGetter, version, token) => {
    return R.ifElse(
        R.either(
            R.compose(R.equals(version), versionGetter),
            R.compose(R.isNil, versionGetter)
        ),
        Either.Right,
        (token) => Either.Left(new TokenVersionError("Token is not at the right version"))
    )(token)
})

/*
  Given the decrypted token, check that the token is not expired
  The check passes if the expiry is undefined (it assumes in that case that there are no expiry checks).
  The function returns the token if the check is successful, else it returns an error.
  The result is wrapped in an Either monad.
  Signature:
  (expiry_getter_fn, get_current_time_in_seconds_fn, decrypted_token) => Either(decrypted_token | TokenExpiryError)
*/
const check_token_expiry = R.curry((expiryGetter, getCurrentTimeInSeconds, token) => {
    return R.ifElse(
        R.either(
            R.converge(R.lt, [getCurrentTimeInSeconds, expiryGetter]),
            R.compose(R.isNil, expiryGetter)
        ),
        Either.Right,
        (token) => Either.Left(new TokenExpiryError("Token is expired"))
    )(token)
})

/*
  Extract the jwt from the authorization header supporting the two following formats:
  Bearer <token>
  <token>
  Signature:
  (string) => string
*/
const extract_auth_header = R.ifElse(
    R.compose(
        (lowercase_header) => lowercase_header.startsWith('bearer '),
        R.toLower
    ),
    (header) => header.substr(7),
    R.identity
)

/*
  Extract the encrypted jwt token from the authorization header.
  Signature:
  (request) => Either(encrypted_token | TokenUndefinedError)
*/
const get_token_from_header = R.compose(
    either_utils.if_nil_else(
        generate_token_undefined_err,
        extract_auth_header
    ),
    R.path(['headers', 'authorization'])
)

/*
  Extract the encrypted jwt token from the cookies.
  This is a higher order function, it takes the jwt cookie key as an argument
  and returns the function that will process cookies.
  Signature:
  (string) => ( (request) => Either(encrypted_token | TokenUndefinedError) )
*/
const get_token_from_cookie = (key) => {
    return R.compose(
        monad_utils.chain(
            either_utils.if_nil_else(
                generate_token_undefined_err,
                R.identity
            )
        ),
        monad_utils.map(R.prop(key)),
        either_utils.if_nil_else(
            generate_token_undefined_err,
            (reqCookie) => cookie.parse(reqCookie)
        ),
        R.path(['headers', 'cookie'])
    )
}

/*
  Unifying encrypted jwt token fetching function that will first attempt to fetch the jwt token from the
  request's authorization header. If that fails, it will attempt to fetch it from the request's cookie.
  It takes the as an argument the key it should use to look for the token in the cookie.
  Signature:
  (string) => ( (request) => Either(encrypted_token | TokenUndefinedError) )
*/
const get_token_anywhere = (key) => {
    const _get_token_from_cookie = get_token_from_cookie(key)
    return (req) => {
        const bearer_token = get_token_from_header(req)
        if(bearer_token.isRight) {
            return bearer_token
        } else {
            return _get_token_from_cookie(req)
        }
    }
}

/*
  Higher order function that given a set of parameters will return a function that will process
  the token of your request.
  It will use the passed functions to:
  - Extract the token from the request (composable via function parameter)
  - Decode the token (internal)
  - Verify that the token has the right version (composable via function parameter)
  - Verify that the token hasn't expired (composable via function parameter)
  Signature:
  (fn, string, fn, fn) => ( (request) => Either(token | Error) )
*/
const process_request_token = R.curry((
    request_token_getter,
    secret,
    versionCheckFn,
    ExpiryCheckFn
) => {
    return R.compose(
        monad_utils.chain(ExpiryCheckFn),
        monad_utils.chain(versionCheckFn),
        monad_utils.chain(decode_token(secret)),
        request_token_getter
    )
})


module.exports = {
    TokenUndefinedError,
    TokenDecodeError,
    TokenVersionError,
    TokenExpiryError,
    decode_token,
    check_token_version,
    check_token_expiry,
    get_token_from_header,
    get_token_from_cookie,
    get_token_anywhere,
    process_request_token,
}