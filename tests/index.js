const { assert } = require('chai')

const jwt = require('jsonwebtoken')
const R = require('ramda')
const Either = require('data.either')

const fn_utils = require('@cr-ste-justine/functional-utils')
const monad_utils = fn_utils.monad

const jwt_utils = require('../index')

describe('Test JWT utilities', () => {
    it('Assert that decoding works on the happy path', () => {
        const token = jwt.sign({ foo: 'bar' }, 'test')
        assert.strictEqual(
            R.compose(
                monad_utils.chain(R.prop('foo')),
                jwt_utils.decode_token('test')
            )(token),
            'bar'
        )
    })

    it('Assert that decoding reports an error on null/undefined tokens', () => {
        assert.instanceOf(
            R.compose(
                monad_utils.value,
                jwt_utils.decode_token('test')
            )(null),
            jwt_utils.TokenDecodeError
        )
        assert.instanceOf(
            R.compose(
                monad_utils.value,
                jwt_utils.decode_token('test')
            )(undefined),
            jwt_utils.TokenDecodeError
        )
    })

    it('Assert that version checks works on the happy path', () => {
        const assert_version_at_1 = jwt_utils.check_token_version(R.prop('version'), 1)

        const token = jwt.sign({ foo: 'bar', version: 1 }, 'test')
        assert.strictEqual(
            R.compose(
                monad_utils.chain(R.prop('foo')),
                monad_utils.chain(assert_version_at_1),
                jwt_utils.decode_token('test')
            )(token),
            'bar'
        )

        const token2 = jwt.sign({ foo: 'bar' }, 'test')
        assert.strictEqual(
            R.compose(
                monad_utils.chain(R.prop('foo')),
                monad_utils.chain(assert_version_at_1),
                jwt_utils.decode_token('test')
            )(token2),
            'bar'
        )
    })

    it('Assert that version checks fail when version does not match', () => {
        const assert_version_at_1 = jwt_utils.check_token_version(R.prop('version'), 1)

        const token = jwt.sign({ foo: 'bar', version: 2 }, 'test')
        assert.instanceOf(
            R.compose(
                monad_utils.value,
                monad_utils.chain(assert_version_at_1),
                jwt_utils.decode_token('test')
            )(token),
            jwt_utils.TokenVersionError
        )
    })

    it('Assert that expiry checks work on the happy path', () => {
        const assert_not_expired_after_20s = jwt_utils.check_token_expiry(R.prop('expiry'), () => 20)

        const token = jwt.sign({ foo: 'bar', expiry: 30 }, 'test')
        assert.strictEqual(
            R.compose(
                monad_utils.chain(R.prop('foo')),
                monad_utils.chain(assert_not_expired_after_20s),
                jwt_utils.decode_token('test')
            )(token),
            'bar'
        )

        const token2 = jwt.sign({ foo: 'bar' }, 'test')
        assert.strictEqual(
            R.compose(
                monad_utils.chain(R.prop('foo')),
                monad_utils.chain(assert_not_expired_after_20s),
                jwt_utils.decode_token('test')
            )(token2),
            'bar'
        )
    })

    it('Assert that expiry check fails when token is expired', () => {
        const assert_not_expired_after_20s = jwt_utils.check_token_expiry(R.prop('expiry'), () => 20)

        const token = jwt.sign({ foo: 'bar', expiry: 10 }, 'test')
        assert.instanceOf(
            R.compose(
                monad_utils.value,
                monad_utils.chain(assert_not_expired_after_20s),
                jwt_utils.decode_token('test')
            )(token),
            jwt_utils.TokenExpiryError
        )
    })

    it('Assert that getting token from the header works on the happy path', () => {
        const token = jwt.sign({ foo: 'bar', expiry: 30, version: 1 }, 'test')
        const request = {
            'headers': {
                'authorization': `Bearer ${token}`
            }
        }

        assert.strictEqual(
            R.compose(
                monad_utils.value,
                jwt_utils.get_token_from_header
            )(request),
            token
        )

        const request2 = {
            'headers': {
                'authorization': `${token}`
            }
        }

        assert.strictEqual(
            R.compose(
                monad_utils.value,
                jwt_utils.get_token_from_header
            )(request2),
            token
        )
    })

    it('Assert that getting token from header reports failure', () =>{
        const request = {
            'headers': {}
        }

        assert.instanceOf(
            R.compose(
                monad_utils.value,
                jwt_utils.get_token_from_header
            )(request),
            jwt_utils.TokenUndefinedError
        )
    })

    it('Assert that getting token from the cookie works on the happy path', () => {
        const token = jwt.sign({ foo: 'bar', expiry: 30, version: 1 }, 'test')
        const request = {
            'headers': {
                'cookie': `foo=bar; jwt=${token}`
            }
        }

        assert.strictEqual(
            R.compose(
                monad_utils.value,
                jwt_utils.get_token_from_cookie('jwt')
            )(request),
            token
        )
    })

    it('Assert that getting token from the cookie reports failure', () =>{
        const token = jwt.sign({ foo: 'bar', expiry: 30, version: 1 }, 'test')
        const request = {
            'headers': {
            }
        }

        assert.instanceOf(
            R.compose(
                monad_utils.value,
                jwt_utils.get_token_from_cookie('jwt')
            )(request),
            jwt_utils.TokenUndefinedError
        )

        const request2 = {
            'headers': {
                'cookie': `foo=bar`
            }
        }

        assert.instanceOf(
            R.compose(
                monad_utils.value,
                jwt_utils.get_token_from_cookie('jwt')
            )(request),
            jwt_utils.TokenUndefinedError
        )

    })

    it('Assert that getting token from anywhere works on the happy path', () => {
        const token = jwt.sign({ foo: 'bar', expiry: 30, version: 1 }, 'test')
        const request = {
            'headers': {
                'cookie': `foo=bar; jwt=${token}`
            }
        }

        assert.strictEqual(
            R.compose(
                monad_utils.value,
                jwt_utils.get_token_anywhere('jwt')
            )(request),
            token
        )

        const request2 = {
            'headers': {
                'authorization': `Bearer ${token}`
            }
        }

        assert.strictEqual(
            R.compose(
                monad_utils.value,
                jwt_utils.get_token_anywhere('jwt')
            )(request2),
            token
        )
    })

    it('Assert that getting token from anywhere works on failure', () => {
        const request = {
            'headers': {
            }
        }

        assert.instanceOf(
            R.compose(
                monad_utils.value,
                jwt_utils.get_token_anywhere('jwt')
            )(request),
            jwt_utils.TokenUndefinedError
        )

        const request2 = {
            'headers': {
                'cookie': `foo=bar`
            }
        }

        assert.instanceOf(
            R.compose(
                monad_utils.value,
                jwt_utils.get_token_anywhere('jwt')
            )(request),
            jwt_utils.TokenUndefinedError
        )
    })

    it('Assert that token processing behaves as expected on full featured the happy path', () => {
        var token = jwt.sign({ foo: 'bar', expiry: 30, version: 1 }, 'test')
        var request = {
            'headers': {
                'authorization': `Bearer ${token}`
            }
        }

        const process = jwt_utils.process_request_token(
            jwt_utils.get_token_from_header,
            'test',
            jwt_utils.check_token_version(R.prop('version'), 1),
            jwt_utils.check_token_expiry(R.prop('expiry'), () => 20)
        )

        assert.strictEqual(
            R.compose(
                monad_utils.chain(R.prop('foo')),
                process
            )(request),
            'bar'
        )
    })

    it('Assert that token processing behaves as expected with version check bypass on the happy path', () => {
        var token = jwt.sign({ foo: 'bar', expiry: 30 }, 'test')
        var request = {
            'headers': {
                'authorization': `Bearer ${token}`
            }
        }

        const process = jwt_utils.process_request_token(
            jwt_utils.get_token_from_header,
            'test',
            Either.Right,
            jwt_utils.check_token_expiry(R.prop('expiry'), () => 20)
        )

        assert.strictEqual(
            R.compose(
                monad_utils.chain(R.prop('foo')),
                process
            )(request),
            'bar'
        )
    })
})