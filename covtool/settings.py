import json

from binaryninja.settings import Settings

my_settings = Settings()
my_settings.register_group("covtool", "CovTool")

# int: example setting
# my_settings.register_setting(
#     "covtool.example_setting",
#     json.dumps(
#         {
#             "title": "Example Setting",
#             "description": "This is an example setting for CovTool.",
#             "default": 1,
#             "type": "number",
#         }
#     ),
# )
