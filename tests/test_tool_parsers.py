import unittest

from ghilliesuite_ex.utils.parsers import (
    parse_dnsx,
    parse_naabu,
    parse_arjun,
    parse_subzy,
    parse_gowitness,
)


class TestToolParsers(unittest.TestCase):
    def test_parse_dnsx_json(self) -> None:
        text = '{"host":"a.example.com","ip":"1.2.3.4"}\n'
        res = parse_dnsx(output=text)
        self.assertEqual(res[0]["domain"], "a.example.com")
        self.assertEqual(res[0]["ip"], "1.2.3.4")

    def test_parse_dnsx_line(self) -> None:
        text = "a.example.com 1.2.3.4\n"
        res = parse_dnsx(output=text)
        self.assertEqual(res[0]["domain"], "a.example.com")
        self.assertEqual(res[0]["ip"], "1.2.3.4")

    def test_parse_naabu_json(self) -> None:
        text = '{"host":"a.example.com","ip":"1.2.3.4","port":443,"protocol":"tcp"}\n'
        res = parse_naabu(output=text)
        self.assertEqual(res[0]["host"], "a.example.com")
        self.assertEqual(res[0]["port"], 443)

    def test_parse_naabu_line(self) -> None:
        text = "a.example.com:80\n"
        res = parse_naabu(output=text)
        self.assertEqual(res[0]["host"], "a.example.com")
        self.assertEqual(res[0]["port"], 80)

    def test_parse_arjun_json(self) -> None:
        text = '[{"url":"https://example.com/api","method":"GET","params":["a","b"]}]'
        res = parse_arjun(output=text)
        self.assertEqual(res[0]["url"], "https://example.com/api")
        self.assertEqual(res[0]["params"], ["a", "b"])

    def test_parse_arjun_line(self) -> None:
        text = "https://example.com/api: a, b\n"
        res = parse_arjun(output=text)
        self.assertEqual(res[0]["url"], "https://example.com/api")
        self.assertIn("a", res[0]["params"])

    def test_parse_arjun_line_with_port(self) -> None:
        text = "https://example.com:8443/api: token, redirect\n"
        res = parse_arjun(output=text)
        self.assertEqual(res[0]["url"], "https://example.com:8443/api")
        self.assertEqual(res[0]["params"], ["token", "redirect"])

    def test_parse_subzy_json(self) -> None:
        text = '{"domain":"a.example.com","status":"VULNERABLE","vulnerable":true}\n'
        res = parse_subzy(output=text)
        self.assertEqual(res[0]["domain"], "a.example.com")
        self.assertTrue(res[0]["vulnerable"])

    def test_parse_subzy_line(self) -> None:
        text = "[VULNERABLE] a.example.com\n"
        res = parse_subzy(output=text)
        self.assertEqual(res[0]["domain"], "a.example.com")
        self.assertTrue(res[0]["vulnerable"])

    def test_parse_subzy_negative_status_is_not_vulnerable(self) -> None:
        text = '{"domain":"safe.example.com","status":"not vulnerable"}\n'
        text += "[NOT VULNERABLE] safe.example.com\n"
        self.assertTrue(all(not row["vulnerable"] for row in parse_subzy(output=text)))

    def test_parse_gowitness_json(self) -> None:
        text = '[{"url":"https://example.com","screenshot":"shot.png","title":"Home","status":200}]'
        res = parse_gowitness(output=text)
        self.assertEqual(res[0]["url"], "https://example.com")
        self.assertEqual(res[0]["status"], 200)


if __name__ == "__main__":
    unittest.main()
