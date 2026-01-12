FROM paritytech/contracts-ci-linux:3.0.1-20231110

WORKDIR /code

COPY . .

CMD ["cargo", "contract", "build", "--release"]
