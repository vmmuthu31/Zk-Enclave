FROM paritytech/contracts-ci-linux:latest

WORKDIR /code

COPY . .

CMD ["cargo", "contract", "build", "--release"]
