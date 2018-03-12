FROM golang:latest 
RUN mkdir /app 
ADD . /app/ 
WORKDIR /app 
RUN go get golang.org/x/crypto/ssh/terminal
RUN go build -o main . 
CMD ["/app/main"]
