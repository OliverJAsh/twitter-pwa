import Validation from 'data.validation';
import { getLatestPublication, getPublicationDate } from '../src/publication';
import { subMilliseconds, setHours, subDays, addDays } from 'date-fns'
import tape from 'blue-tape';

const timeout = duration => new Promise(resolve => setTimeout(resolve, duration))

const add = (x, y) => x + y
const meanDates = dates => {
    const sum = dates
        .map(date => date.getTime())
        .reduce(add)
    return new Date(sum / dates.length)
}

const getPublicationRange = publicationDate => {
    const publicationUpperBoundDate = subMilliseconds(publicationDate, 1)
    return [ publicationDate, publicationUpperBoundDate ];
}

tape('should only retrieve tweets in range', async assert => {
    const publicationDate = getPublicationDate();
    const previousPublicationDate = subDays(publicationDate, 1);
    const nextPublicationDate = addDays(publicationDate, 1);
    const dateInPublication = meanDates(getPublicationRange(publicationDate));
    const dateInPreviousPublication = meanDates(getPublicationRange(previousPublicationDate));
    const dateInNextPublication = meanDates(getPublicationRange(nextPublicationDate));
    const tweetInPublication = { id_str: 'c', created_at: dateInPublication.toISOString() };
    const createPagesGenerator = async function* () {
        yield Promise.resolve(Validation.of([
            { id_str: 'd', created_at: dateInNextPublication.toISOString() },
        ]));
        yield Promise.resolve(Validation.of([
            tweetInPublication,
            { id_str: 'b', created_at: dateInPreviousPublication.toISOString() },
        ]))
        yield Promise.resolve(Validation.of([
            { id_str: 'a', created_at: dateInPreviousPublication.toISOString() },
        ]));
    }

    const pages = createPagesGenerator()
    const result = await getLatestPublication(pages);

    result.fold(
        apiErrorsList => assert.fail(`Unexpected API errors: ${JSON.stringify(apiErrorsList, null, '\t')}`),
        tweets => {
            assert.ok(tweets.length === 1)
            assert.ok(tweets.every(tweet => tweet === tweetInPublication))
        }
    )
})
