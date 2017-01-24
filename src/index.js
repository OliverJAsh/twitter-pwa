import { FunctifiedAsync } from './functify'
import { Server, createServer } from 'http';
import express from 'express';
import fetch from 'node-fetch';
import { randomBytes as randomBytesCb } from 'crypto';
import denodeify from 'denodeify';
import { toPairs, sortBy } from 'lodash';
import { createHmac } from 'crypto';
import session from 'express-session';

const randomBytes = denodeify(randomBytesCb);

const app = express();

app.use(session({ secret: 'keyboard cat' }));

const twitterConsumerKey = process.env.TWITTER_CONSUMER_KEY;
const twitterConsumerSecret = process.env.TWITTER_CONSUMER_SECRET;
const twitterCallbackURL = 'http://127.0.0.1:8080/auth/callback';
const twitterApiURL = 'https://api.twitter.com';

// https://dev.twitter.com/oauth/overview/creating-signatures
const createOauthSignature = ({ method, baseUrl, parameters, oauthTokenSecret }) => {
    const parametersString = sortBy(
        toPairs(parameters)
            .map(([ key, value ]) => [ encodeURIComponent(key), encodeURIComponent(value) ]),
        ([ key, value ]) => key
    )
        .map(pair => pair.join('='))
        .join('&');

    const signatureBaseString = `${method}&${encodeURIComponent(baseUrl)}&${encodeURIComponent(parametersString)}`;
    const signingKey = `${encodeURIComponent(twitterConsumerSecret)}&${encodeURIComponent(oauthTokenSecret)}`
    const signature = createHmac('sha1', signingKey).update(signatureBaseString).digest('base64')

    return signature;
};

const createNonce = () => randomBytes(32).then(buffer => (
    buffer.toString('base64').replace(/[^\w]/g, '')
));

const stringifyQueryParamsObj = (oauthParams) => (
    toPairs(oauthParams)
        .map(([ key, value ]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
        .join('&')
);

const oauthHeaderFromObj = (oauthParams) => (
    toPairs(oauthParams)
        .map(([ key, value ]) => `${encodeURIComponent(key)}="${encodeURIComponent(value)}"`)
        .join(', ')
);

// https://dev.twitter.com/oauth/overview/authorizing-requests#collecting-parameters
const getOauthParams = (maybeOAuthRequestOrAccessToken) => (
    createNonce().then(nonce => (
        Object.assign({}, {
            oauth_callback: twitterCallbackURL,
            oauth_consumer_key: twitterConsumerKey,
            oauth_nonce: nonce,
            oauth_signature_method: 'HMAC-SHA1',
            oauth_timestamp: parseInt((Date.now() / 1000).toFixed(0)),
            oauth_version: '1.0',
        }, (
            maybeOAuthRequestOrAccessToken !== undefined
                ? { oauth_token: maybeOAuthRequestOrAccessToken, }
                : {}
        ))
    ))
);

const fetchFromTwitter = ({
    oauthParams,
    oauthAccessTokenSecret,
    baseUrlPath,
    method,
    otherParams,
}) => {
    const baseUrl = `${twitterApiURL}${baseUrlPath}`;
    const parameters = Object.assign({}, oauthParams, otherParams);
    const oauthSignature = createOauthSignature({
        method,
        baseUrl,
        parameters,
        oauthTokenSecret: oauthAccessTokenSecret
    });
    const oauthHeader = oauthHeaderFromObj(
        Object.assign({}, oauthParams, { oauth_signature: oauthSignature })
    );

    const paramsStr = Object.keys(otherParams).length > 0
        ? `?${stringifyQueryParamsObj(otherParams)}`
        : '';
    const url = `${baseUrl}${paramsStr}`;
    return fetch(url, {
        method,
        headers: { 'Authorization': `OAuth ${oauthHeader}` }
    })
}

const getRequestToken = () => {
    return getOauthParams().then(oauthParams => {
        return fetchFromTwitter({
            oauthParams,
            oauthAccessTokenSecret: '',
            baseUrlPath: `/oauth/request_token`,
            method: 'POST',
            otherParams: {},
        })
            .then(response => response.text().then(text => {
                if (response.ok) {
                    const pairs = text
                        .split('&')
                        .map(item => item.split('='))
                    return {
                        oauthToken: pairs.find(([ key, value ]) => key === 'oauth_token')[1],
                        oauthTokenSecret: pairs.find(([ key, value ]) => key === 'oauth_token_secret')[1],
                        oauthCallbackConfirmed: pairs.find(([ key, value ]) => key === 'oauth_callback_confirmed')[1]
                    }
                } else {
                    throw new Error(`Bad response from Twitter: ${response.status} ${text}`)
                }
            }))
    });
}

const getAccessToken = ({ oauthRequestToken, oauthVerifier }) => {
    return getOauthParams(oauthRequestToken).then(oauthParams => {
        return fetchFromTwitter({
            oauthParams,
            oauthAccessTokenSecret: '',
            baseUrlPath: `/oauth/access_token?oauth_verifier=${oauthVerifier}`,
            method: 'POST',
            otherParams: {},
        })
            .then(response => response.text().then(text => {
                if (response.ok) {
                    const pairs = text
                        .split('&')
                        .map(item => item.split('='))
                    return {
                        oauthToken: pairs.find(([ key, value ]) => key === 'oauth_token')[1],
                        oauthTokenSecret: pairs.find(([ key, value ]) => key === 'oauth_token_secret')[1],
                        userId: pairs.find(([ key, value ]) => key === 'user_id')[1],
                        screenName: pairs.find(([ key, value ]) => key === 'screen_name')[1],
                        xAuthExpires: pairs.find(([ key, value ]) => key === 'x_auth_expires')[1]
                    }
                } else {
                    throw new Error(`Bad response from Twitter: ${response.status} ${text}`)
                }
            }))
    });
};

const flatten = (xs) => xs.reduce((acc, value) => acc.concat(value), [])

const getWholeTimeline = ({ oauthAccessToken, oauthAccessTokenSecret }) => {
    return getOauthParams(oauthAccessToken).then(oauthParams => {
        const pageThroughTwitterTimeline = async function* () {
            const recurse = async function* (maybeMaxId = undefined) {
                const response = await fetchFromTwitter({
                    oauthParams,
                    oauthAccessTokenSecret,
                    baseUrlPath: '/1.1/statuses/home_timeline.json',
                    method: 'GET',
                    // 200 is max
                    otherParams: Object.assign({},
                        {
                            count: 200,
                        },
                        maybeMaxId !== undefined ? { max_id: maybeMaxId } : {}
                    )
                })
                const json = await response.json();
                if (response.ok) {
                    yield json;
                    const maybeLastTweet = json[json.length - 1];
                    if (maybeLastTweet) {
                        const lastTweet = maybeLastTweet;
                        yield* recurse(lastTweet.id_str)
                    } else {
                        throw new Error('Expected last tweek')
                    }
                } else {
                    throw new Error(`Bad response from Twitter: ${response.status} ${JSON.stringify(json, null, '\t')}`)
                }
            }

            yield* recurse()
        }

        const resultsPromise = new FunctifiedAsync(pageThroughTwitterTimeline())
            .take(4)
            .toArray();
        return resultsPromise.then(flatten)
    })
};

const getTimeline = ({ oauthAccessToken, oauthAccessTokenSecret }) => {
    return getOauthParams(oauthAccessToken).then(oauthParams => {
        return fetchFromTwitter({
            oauthParams,
            oauthAccessTokenSecret,
            baseUrlPath: '/1.1/statuses/home_timeline.json',
            method: 'GET',
            // 200 is max
            otherParams: {
                count: 200,
            },
        })
            .then(response => response.json().then(json => {
                if (response.ok) {
                    // TODO: Model json
                    return json;
                } else {
                    throw new Error(`Bad response from Twitter: ${response.status} ${JSON.stringify(json, null, '\t')}`)
                }
            }))
    });
};

// https://dev.twitter.com/web/sign-in/implementing
app.get('/auth', (req, res, next) => {
    getRequestToken()
        .then(requestTokenResponse => (
            res
                .status(302)
                .location(`${twitterApiURL}/oauth/authenticate?oauth_token=${requestTokenResponse.oauthToken}`)
                .end()
        ))
        .catch(next);
});
app.get('/auth/callback', (req, res, next) => {
    getAccessToken({ oauthRequestToken: req.query.oauth_token, oauthVerifier: req.query.oauth_verifier })
        .then(accessTokenResponse => {
            // TODO:
            req.session.oauthAccessToken = accessTokenResponse.oauthToken;
            req.session.oauthAccessTokenSecret = accessTokenResponse.oauthTokenSecret;
            res.redirect('/');
        })
        .catch(next);
});
app.get('/', (req, res, next) => {
    // TODO: If logged in helper
    if (req.session.oauthAccessToken) {
        getWholeTimeline({
            oauthAccessToken: req.session.oauthAccessToken,
            oauthAccessTokenSecret: req.session.oauthAccessTokenSecret
        })
            .then(tweets => {
                res.send((
                    `<ul>${tweets.map((tweet) => (
                        `<li>${tweet.created_at} @${tweet.user.screen_name}: ${tweet.text}</li>`
                    )).join('')}</ul>`
                ));
            })
            .catch(next);
    } else {
        res.send('Not authenticated');
    }
})

const onListen = (server) => {
    const { port } = server.address();

    console.log(`Server running on port ${port}`);
};

const httpServer = createServer(app);
httpServer.listen(8080, () => onListen(httpServer));
