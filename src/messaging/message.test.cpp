#include <catch2/catch.hpp>
import securemsg.messaging.message;

TEST_CASE("Message construction and getters", "[message]") {
    Message m{1, 2, 3, "ct", "hdr", 1000, Message::Direction::Received};
    REQUIRE(m.getId()               == 1);
    REQUIRE(m.getSenderId()         == 2);
    REQUIRE(m.getRecipientId()      == 3);
    REQUIRE(m.getCiphertext()       == "ct");
    REQUIRE(m.getRatchetHeaderEnc() == "hdr");
    REQUIRE(m.getSentAt()           == 1000);
    REQUIRE(m.getDirection()        == Message::Direction::Received);
    REQUIRE(m.getPlaintext()        == "");
}

TEST_CASE("Message setPlaintext", "[message]") {
    Message m{1, 2, 3, "ct", "hdr", 0, Message::Direction::Sent};
    m.setPlaintext("hello");
    REQUIRE(m.getPlaintext() == "hello");
}

TEST_CASE("Message Direction enum values distinct", "[message]") {
    REQUIRE(Message::Direction::Sent != Message::Direction::Received);
}

TEST_CASE("GroupMessage construction and getters", "[message]") {
    GroupMessage gm{1, 10, 2, "ct", 9999};
    REQUIRE(gm.getId()         == 1);
    REQUIRE(gm.getGroupId()    == 10);
    REQUIRE(gm.getEpoch()      == 2);
    REQUIRE(gm.getCiphertext() == "ct");
    REQUIRE(gm.getSentAt()     == 9999);
    REQUIRE(gm.getPlaintext()  == "");
}

TEST_CASE("GroupMessage setPlaintext", "[message]") {
    GroupMessage gm{1, 10, 2, "ct", 0};
    gm.setPlaintext("hello group");
    REQUIRE(gm.getPlaintext() == "hello group");
}
