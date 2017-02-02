export class FunctifiedAsync {
    constructor(iterable) {
        this.iterable = iterable;
    }

    async *[Symbol.asyncIterator]() {
        for await (const value of this.iterable) {
            yield value;
        }
    }

    map(callback) {
        const iterable = this.iterable;
        return FunctifiedAsync.fromGenerator(async function* () {
            for await (const value of iterable) {
                yield callback(value);
            }
        });
    }


    dropWhile(predicate) {
        const iterable = this.iterable;
        return FunctifiedAsync.fromGenerator(async function* () {
            let skip = true;
            for await (const value of iterable) {
                if (!predicate(value)) {
                    skip = false;
                }
                if (!skip) {
                    yield value;
                }
            }
        });
    }

    flatten() {
        const iterable = this.iterable;
        return FunctifiedAsync.fromGenerator(async function* () {
            for await (const value of iterable) {
                if (value[Symbol.iterator] || value[Symbol.asyncIterator]) {
                    yield* new FunctifiedAsync(value);
                } else {
                    yield value;
                }
            }
        });
    }

    take(n) {
        const iterator = this.iterable[Symbol.asyncIterator]();
        const self = this;
        return FunctifiedAsync.fromGenerator(async function* () {
            let i = 0;
            if (self.hasOwnProperty("startValue")) {
                yield self.startValue;
                i++;
            }
            while (i < n) {
                const result = await iterator.next();
                if (result.done) {
                    break;
                } else {
                    yield result.value;
                    i++;
                }
            }
        });
    }

    takeUntil(predicate) {
        const iterator = this.iterable[Symbol.asyncIterator]();
        const self = this;
        return FunctifiedAsync.fromGenerator(async function* () {
            if (self.hasOwnProperty("startValue")) {
                yield self.startValue;
            }
            while (true) {
                const result = await iterator.next();
                if (result.done) {
                    break;
                } else {
                    if (predicate(result.value)) {
                        // save the value so we can yield if takeUntil is called again
                        self.startValue = result.value;
                        break;
                    } else {
                        yield result.value;
                    }
                }
            }
        });
    }

    async reduce(callback, initialValue) {
        let accum = initialValue;
        const iterator = this.iterable[Symbol.asyncIterator]();

        while (true) {
            const result = await iterator.next();
            if (result.done) {
                break;
            } else {
                accum = callback(accum, result.value);
            }
        }

        return accum;
    }

    toArray() {
        return this.reduce((acc, value) => {
            acc.push(value);
            return acc;
        }, [])
    }

    static fromGenerator(generator) {
        return new FunctifiedAsync({
            [Symbol.asyncIterator]: generator
        });
    }
}
