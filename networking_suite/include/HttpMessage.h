//
// Created by maxim on 10.09.2024.
//

// HttpMessage.h
#pragma once
#include "HttpHeader.h"
#include "HttpBody.h"
#include <string>

class HttpMessage {
public:
    enum class Type { REQUEST, RESPONSE };

    HttpMessage(Type type) : type_(type) {}

    void setType(Type type) {
        type_ = type;
    }

    Type getType() const {
        return type_;
    }

    HttpHeader& header() {
        return header_;
    }

    const HttpHeader& header() const {
        return header_;
    }

    HttpBody& body() {
        return body_;
    }

    const HttpBody& body() const {
        return body_;
    }

    virtual std::string toString() const = 0;

protected:
    Type type_;
    HttpHeader header_;
    HttpBody body_;
};


