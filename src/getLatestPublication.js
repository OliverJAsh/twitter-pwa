import Validation from 'data.validation';
import { uniqBy } from 'lodash';
import { subDays } from 'date-fns'
import { FunctifiedAsync } from './functify'

// Array<Validation<A, B>> => Validation<Array<A>, Array<B>>
// https://github.com/origamitower/folktale/issues/71
const sequenceValidations = validations => (
    validations
        .reduce((acc, validation) => (
            Validation.Success(a => b => a.concat(b)).ap(acc).ap(validation)
        ), Validation.of([]))
)

// TODO: Dedupe
const limit = 800;
// This is the max allowed
// TODO: Dedupe
const pageSize = 200;

const getPublicationDate = () => {
    const nowDate = new Date()
    const publicationHour = 6
    const isTodaysDueForPublication = nowDate.getHours() >= publicationHour
    // If the time is the past publication hour, the publication date is
    // today else it is yesterday.
    const publicationDate = new Date(
        nowDate.getFullYear(),
        nowDate.getMonth(),
        nowDate.getDate() - (isTodaysDueForPublication ? 0 : 1),
        publicationHour
    )
    return publicationDate;
}

// Tweet = { id_str: string, created_at: string }
export const getLatestPublication = async (pages) => { // pages = AsyncIterable<ApiResponse<Tweet[]>>
    const publicationDate = getPublicationDate();
    const previousPublicationDate = subDays(publicationDate, 1);

    // Lazily page through tweets in the timeline to find the publication
    // range.
    // Array<ApiResponse<Tweet>>
    const tweetApiResponses = await new FunctifiedAsync(pages)
        // We request by max ID, and since the response is inclusive of the max
        // ID tweet, the paging could continue infinitely. This prevents that.
        // We're not forcing x requests, this is a limit applied lazily.
        .take(Math.ceil(limit / pageSize))
        // Move the array to the outside, so we can flatten the inner iterable
        // AsyncIterable<Validation<Left, Array<Right>>> => AsyncIterable<Array<Validation<Left, Right>>>
        // AsyncIterable<ApiResponse<Array<Tweet>>> => AsyncIterable<Array<ApiResponse<Tweet>>>
        .map(apiResponse => (
            apiResponse.fold(
                apiErrorsList => [Validation.Failure(apiErrorsList)],
                tweets => tweets.map(tweet => Validation.Success(tweet))
            )
        ))
        .flatten() // AsyncIterable<Array<ApiResponse<Tweet>>> => AsyncIterable<ApiResponse<Tweet>>
        .dropWhile(apiResponse => (
            apiResponse
                .map(tweet => new Date(tweet.created_at) >= publicationDate)
                .getOrElse(false)
        ))
        // TODO: Rename to takeWhile
        .takeUntil(apiResponse => (
            apiResponse
                .map(tweet => new Date(tweet.created_at) < previousPublicationDate)
                .getOrElse(false)
        ))
        .toArray();
    const tweetsApiResponse = sequenceValidations(tweetApiResponses)
        // Since the max ID parameter is inclusive, there will be duplicates where
        // the pages interleave. This removes them.
        .map(tweets => uniqBy(tweets, tweet => tweet.id_str))

    return tweetsApiResponse;
};
