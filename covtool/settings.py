import json

from binaryninja.settings import Settings

my_settings = Settings()
my_settings.register_group("covtool", "CovTool")

# default highlight color
my_settings.register_setting(
    "covtool.defaultHighlightColor",
    json.dumps(
        {
            "title": "default highlight color",
            "description": "default color for coverage highlighting",
            "default": "orange",
            "type": "string",
            "enum": ["orange", "cyan", "red", "blue", "green", "magenta", "yellow"],
            "enumDescriptions": [
                "orange (default)",
                "cyan",
                "red",
                "blue",
                "green",
                "magenta",
                "yellow",
            ],
        }
    ),
)

# heatmap percentile cap
my_settings.register_setting(
    "covtool.heatmapPercentileCap",
    json.dumps(
        {
            "title": "heatmap percentile cap",
            "description": "percentile at which to cap hitcounts for heatmap visualization (e.g., 95 means cap at 95th percentile)",
            "default": 95,
            "type": "number",
            "minValue": 50,
            "maxValue": 100,
        }
    ),
)

# use logarithmic scale for heatmap
my_settings.register_setting(
    "covtool.heatmapLogScale",
    json.dumps(
        {
            "title": "use logarithmic scale",
            "description": "use logarithmic scale for heatmap color interpolation",
            "default": True,
            "type": "boolean",
        }
    ),
)

# show coverage stats in log
my_settings.register_setting(
    "covtool.showStatsInLog",
    json.dumps(
        {
            "title": "show coverage stats in log",
            "description": "display coverage statistics in the log after importing",
            "default": True,
            "type": "boolean",
        }
    ),
)
