from __future__ import annotations

import pandas as pd

from dylibscope.config.ios_versions import IOS_VERSION, VERSION_ORDER
from dylibscope.config.versioning import normalize_ios_versions, normalize_version_label


def test_normalize_version_label_maps_known_raw_version():
    assert normalize_version_label("iPhone5,1_8.0_12A365") == "iOS 8.0"


def test_normalize_version_label_strips_whitespace():
    assert normalize_version_label("  iPhone5,1_8.0_12A365  ") == "iOS 8.0"


def test_normalize_version_label_preserves_unknown_version():
    assert normalize_version_label("custom_version") == "custom_version"


def test_normalize_version_label_converts_non_string_input():
    assert normalize_version_label(123) == "123"


def test_normalize_ios_versions_maps_raw_labels_to_readable_labels():
    df = pd.DataFrame(
        {
            IOS_VERSION: [
                "iPhone5,1_8.0_12A365",
                "iPhone5,1_9.0_13A344",
            ],
            "library": ["libA.dylib", "libB.dylib"],
        }
    )

    result = normalize_ios_versions(df)

    assert list(result[IOS_VERSION].astype(str)) == ["iOS 8.0", "iOS 9.0"]


def test_normalize_ios_versions_preserves_original_dataframe():
    df = pd.DataFrame(
        {
            IOS_VERSION: ["iPhone5,1_8.0_12A365"],
            "library": ["libA.dylib"],
        }
    )

    result = normalize_ios_versions(df)

    assert df is not result
    assert df.loc[0, IOS_VERSION] == "iPhone5,1_8.0_12A365"
    assert str(result.loc[0, IOS_VERSION]) == "iOS 8.0"


def test_normalize_ios_versions_uses_ordered_categorical():
    df = pd.DataFrame(
        {
            IOS_VERSION: [
                "iPhone5,1_9.0_13A344",
                "iPhone5,1_8.0_12A365",
            ]
        }
    )

    result = normalize_ios_versions(df)

    assert result[IOS_VERSION].dtype.ordered
    assert list(result[IOS_VERSION].cat.categories) == VERSION_ORDER


def test_normalize_ios_versions_converts_unknown_version_to_nan_category():
    df = pd.DataFrame(
        {
            IOS_VERSION: ["unknown_version"],
        }
    )

    result = normalize_ios_versions(df)

    assert result[IOS_VERSION].isna().iloc[0]