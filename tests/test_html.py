from html.parser import HTMLParser
from pathlib import Path
import unittest


HTML_FILE = Path(__file__).resolve().parents[1] / "cybersecurity-ai-agent.html"


class DashboardParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = []
        self.links = []
        self.title_text = []
        self.in_title = False
        self.has_viewport = False
        self.has_main = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "a":
            self.links.append(attrs.get("href", ""))
        if tag == "title":
            self.in_title = True
        if tag == "meta" and attrs.get("name", "").lower() == "viewport":
            self.has_viewport = True
        if tag == "main":
            self.has_main = True

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_text.append(data.strip())


class DashboardIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = HTML_FILE.read_text(encoding="utf-8")
        cls.parser = DashboardParser()
        cls.parser.feed(cls.source)
        cls.parser.close()

    def test_html_file_exists_and_is_nonempty(self):
        self.assertTrue(HTML_FILE.is_file())
        self.assertTrue(self.source.strip())

    def test_document_has_title_viewport_and_main_landmark(self):
        self.assertTrue(any(self.parser.title_text), "A descriptive page title is required")
        self.assertTrue(self.parser.has_viewport, "Responsive viewport metadata is required")
        self.assertTrue(self.parser.has_main, "A main landmark is required")

    def test_ids_are_unique(self):
        duplicates = sorted({item for item in self.parser.ids if self.parser.ids.count(item) > 1})
        self.assertEqual(duplicates, [], f"Duplicate HTML id attributes: {duplicates}")

    def test_local_navigation_targets_exist(self):
        known_ids = set(self.parser.ids)
        missing = [
            href for href in self.parser.links
            if href.startswith("#") and len(href) > 1 and href[1:] not in known_ids
        ]
        self.assertEqual(missing, [], f"Broken in-page links: {missing}")

    def test_prototype_discloses_simulated_status(self):
        lowered = self.source.lower()
        self.assertTrue(
            "simulat" in lowered or "demonstration" in lowered or "prototype" in lowered,
            "Prototype should clearly disclose its non-production status",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
