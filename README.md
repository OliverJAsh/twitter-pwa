# Twitter PWA

Auth using Sign In with Twitter (not 3 legged)
https://dev.twitter.com/web/sign-in/implementing

## Usage

```
yarn
TWITTER_CONSUMER_KEY= TWITTER_CONSUMER_SECRET= yarn start
```

# Design

Twitter's timeline API is limited to 800 tweets. Therefore we have some edge
cases that require explanation to the user:

- Range exists within available tweets.
- Range begins after the last available tweet.
  Heuristic: available tweets since range start length > range length.
  E.g. if desired range is tweets from yesterday and all available tweets are from today.
- Range begins in available tweets but possibly ends after the last available
  tweet.
  Heuristic: last available tweet === last tweet in range
