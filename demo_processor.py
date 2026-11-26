"""Canned responses for the two fictional sample rows only."""


class DemoProcessor:
    def __init__(self, secret):
        pass

    def observe(self, file_id, loc, data):
        if data not in ({"patient_name": "Demo Canary Alpha", "medicine": "Dolo 650"},
                        {"patient_name": "Demo Canary Beta", "medicine": "Dolo 650"}):
            raise ValueError("unrecognized demo record")

    def finish(self):
        pass

    def clean(self, file_id, loc, data):
        self.observe(file_id, loc, data)
        return {"patient_name": "[REDACTED]", "medicine": "Dolo 650"}, None
