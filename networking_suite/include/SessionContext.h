//
// Created by maxim on 09.09.2024.
//
#pragma once

using ByteVector = std::vector<uint8_t>;

class MessageFraming
{
public:
    virtual ~MessageFraming() = default;
    [[nodiscard]] virtual ByteVector frameMessage(const ByteVector& message) const = 0;
    [[nodiscard]] virtual bool isCompleteMessage(const ByteVector& buffer) const = 0;
    virtual ByteVector extractMessage(const ByteVector& buffer) = 0;
};


template<typename SessionType, typename SenderFramingType, typename ReceiverFramingType>
class SessionContext
{
public:
    SessionContext(const SessionContext &other)
        : session_(other.session_),
          connected_callback_(other.connected_callback_),
          closed_callback_(other.closed_callback_),
          message_handler_(other.message_handler_),
          send_framing_(other.send_framing_),
          receive_framing_(other.receive_framing_),
          write_preprocessor_(other.write_preprocessor_),
          read_postprocessor_(other.read_postprocessor_),
          is_complete_message_check_(other.is_complete_message_check_)
    {
    }

    SessionContext(SessionContext &&other) noexcept
        : session_(std::move(other.session_)),
          connected_callback_(std::move(other.connected_callback_)),
          closed_callback_(std::move(other.closed_callback_)),
          message_handler_(std::move(other.message_handler_)),
          send_framing_(std::move(other.send_framing_)),
          receive_framing_(std::move(other.receive_framing_)),
          write_preprocessor_(std::move(other.write_preprocessor_)),
          read_postprocessor_(std::move(other.read_postprocessor_)),
          is_complete_message_check_(std::move(other.is_complete_message_check_))
    {
    }

    SessionContext & operator=(const SessionContext &other)
    {
        if (this == &other)
            return *this;
        session_ = other.session_;
        connected_callback_ = other.connected_callback_;
        closed_callback_ = other.closed_callback_;
        message_handler_ = other.message_handler_;
        send_framing_ = other.send_framing_;
        receive_framing_ = other.receive_framing_;
        write_preprocessor_ = other.write_preprocessor_;
        read_postprocessor_ = other.read_postprocessor_;
        is_complete_message_check_ = other.is_complete_message_check_;
        return *this;
    }

    SessionContext & operator=(SessionContext &&other) noexcept
    {
        if (this == &other)
            return *this;
        session_ = std::move(other.session_);
        connected_callback_ = std::move(other.connected_callback_);
        closed_callback_ = std::move(other.closed_callback_);
        message_handler_ = std::move(other.message_handler_);
        send_framing_ = std::move(other.send_framing_);
        receive_framing_ = std::move(other.receive_framing_);
        write_preprocessor_ = std::move(other.write_preprocessor_);
        read_postprocessor_ = std::move(other.read_postprocessor_);
        is_complete_message_check_ = std::move(other.is_complete_message_check_);
        return *this;
    }

    using ConnectedCallback = std::function<void(const std::shared_ptr<SessionType> &port)>;
    using ClosedCallback = std::function<void(const std::shared_ptr<SessionType> &port)>;
    using MessageHandler = std::function<void(const std::shared_ptr<SessionType> &port, const ByteVector &)>;
    using PreProcessor = std::function<ByteVector(const ByteVector &)>;
    using PostProcessor = std::function<ByteVector(const ByteVector &)>;
    using IsCompleteMessageCheck= std::function<bool(const ByteVector&)>;

        SessionContext() = default;
    ~SessionContext() = default;



    void set_connected_callback(ConnectedCallback callback)
    {
        connected_callback_ = std::move(callback);
    }

    void set_closed_callback(ClosedCallback callback)
    {
        closed_callback_ = std::move(callback);
    }

    void set_message_handler(MessageHandler handler)
    {
        message_handler_ = std::move(handler);
    }

    SenderFramingType& get_message_framing_send()
    {
        return send_framing_;
    }

    ReceiverFramingType& get_message_framing_receive()
    {
        return receive_framing_;
    }


    void set_message_framing_sender(SenderFramingType send_framing)
    {
        send_framing_ = std::move(send_framing);
        set_write_preprocessor([this](const ByteVector& msg) {
            return this->send_framing_.frameMessage(msg);
        });
    }

    void set_message_framing_receiver(ReceiverFramingType receive_framing)
    {
        receive_framing_ = std::move(receive_framing);
        set_read_postprocessor([this](const ByteVector& msg) {
            return this->receive_framing_.extractMessage(msg);
        });
        set_is_complete_message_check([this](const ByteVector& msg) {
            return this->receive_framing_.isCompleteMessage(msg);
        });
    }

    void on_connect()
    {
        if (connected_callback_)
        {
            connected_callback_(session_);
        }
    }

    void on_close()
    {
        if (closed_callback_)
        {
            closed_callback_(session_);
        }
    }

    void on_message(const ByteVector &data)
    {
        if (message_handler_)
        {
            message_handler_(session_, data);
        }
    }

    [[nodiscard]] ByteVector preprocess_write(const ByteVector &data) const
    {
        return write_preprocessor_ ? write_preprocessor_(data) : data;
    }

    [[nodiscard]] ByteVector postprocess_read(const ByteVector &data) const
    {
        return read_postprocessor_ ? read_postprocessor_(data) : data;
    }

    [[nodiscard]] bool checkIfIsCompleteMessage(const ByteVector &data) const
    {
        return is_complete_message_check_ ? is_complete_message_check_(data) : true;
    }
    void set_port(std::shared_ptr<SessionType> port)
    {
        session_ = std::move(port);
    }

private:
    void set_write_preprocessor(PreProcessor processor)
    {
        write_preprocessor_ = std::move(processor);
    }

    void set_read_postprocessor(PostProcessor processor)
    {
        read_postprocessor_ = std::move(processor);
    }

    void set_is_complete_message_check(IsCompleteMessageCheck is_complete_message)
    {
        is_complete_message_check_ = std::move(is_complete_message);
    }

    std::shared_ptr<SessionType> session_{};
    ConnectedCallback connected_callback_{};
    ClosedCallback closed_callback_{};
    MessageHandler message_handler_{};

    SenderFramingType send_framing_;
    ReceiverFramingType receive_framing_;

    PreProcessor write_preprocessor_;
    PostProcessor read_postprocessor_;

    IsCompleteMessageCheck is_complete_message_check_;
};
