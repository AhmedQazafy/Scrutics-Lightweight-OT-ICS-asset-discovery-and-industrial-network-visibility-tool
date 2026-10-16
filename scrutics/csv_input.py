"""Settings every Scrutics CSV reader applies before reading."""

import csv

# The session exporter can write cells far larger than the csv module's default limit of 131,072
# characters, for example a long evidence summary. 2**31 - 1 fits a C long on every platform,
# including Windows builds that reject sys.maxsize.
FIELD_LIMIT = 2**31 - 1


def allow_large_fields() -> None:
    """Let the csv module read cells up to FIELD_LIMIT characters.

    The limit is process-wide; it is only ever raised, so a larger limit set elsewhere is kept.
    """
    if csv.field_size_limit() < FIELD_LIMIT:
        csv.field_size_limit(FIELD_LIMIT)
