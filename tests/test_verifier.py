import verifier as v


def test_parse_list_splits_and_dedupes():
    assert v.parse_list("a@x.com, b@y.org;\nA@x.com <c@z.io>") == ["a@x.com", "b@y.org", "c@z.io"]


def test_syntax():
    assert v.check_syntax("jane.doe+tag@example.co.uk") is None
    for bad in ["plain", "a@@b.com", "a..b@c.com", ".a@c.com", "a@b", "a@-b.com", "a@b.c0m"]:
        assert v.check_syntax(bad), bad


def test_classify():
    assert v.classify_rcpt(250) == "accepted"
    assert v.classify_rcpt(550, "5.1.1 user unknown") == "rejected"
    assert v.classify_rcpt(550, "5.7.1 blocked by policy") == "unclear"
    assert v.classify_rcpt(451, "try later") == "unclear"


def test_invalid_and_typo_need_no_network():
    r = v.check_many(["nope", "bob@gmial.com"], smtp=False)
    assert [x["status"] for x in r] == ["bounce", "bounce"]
    assert "gmail.com" in r[1]["reason"]
