use serde::Deserialize;

/// `GET https://profile.xboxlive.com/users/me/profile/settings?settings=GameDisplayPicRaw` -
/// `profile.xboxlive.com` falls under the `*.xboxlive.com` wildcard entry in
/// `title.mgt.xboxlive.com`'s endpoint table (same `http://xboxlive.com` relying party every
/// other plain Xbox Live call in this crate already uses), so no new endpoint authorization is
/// needed beyond the XSTS token callers already have. `settings[].value` is a URL to the raw
/// picture bytes on a separate, unauthenticated image CDN - this struct only carries that URL,
/// [`get_gamer_picture`] does the second fetch.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileSettingsResponse {
    profile_users: Vec<ProfileUser>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileUser {
    #[serde(default)]
    settings: Vec<ProfileSetting>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileSetting {
    id: String,
    value: String,
}

/// `XUserGetGamerPictureAsync`'s real backing. `xsts_header` is the same
/// `XBL3.0 x=...;<token>` value [`super::get_xsts_auth_header`] produces for any other
/// `*.xboxlive.com` call. Returns `Ok(None)` when the account has no `GameDisplayPicRaw`
/// setting (e.g. a fresh account with no picture claim) - an honest absence, not an error.
///
/// The real GDK signature also takes an `XUserGamerPictureSize` (Small/Medium/Large/ExtraLarge).
/// `GameDisplayPicRaw`'s CDN URL is known to accept resizing query parameters in some contexts,
/// but which ones the real client sends for each `XUserGamerPictureSize` value is not known -
/// rather than guessing a query string, this returns the one canonical picture Xbox Live sized for
/// display use, for every requested size.
pub async fn get_gamer_picture(
    client: &reqwest::Client,
    xsts_header: &str,
) -> reqwest::Result<Option<Vec<u8>>> {
    let settings: ProfileSettingsResponse = client
        .get("https://profile.xboxlive.com/users/me/profile/settings")
        .query(&[("settings", "GameDisplayPicRaw")])
        .header("x-xbl-contract-version", "3")
        .header("Authorization", xsts_header)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let Some(url) = settings
        .profile_users
        .first()
        .and_then(|user| user.settings.iter().find(|s| s.id == "GameDisplayPicRaw"))
        .map(|s| s.value.clone())
        .filter(|url| !url.is_empty())
    else {
        return Ok(None);
    };

    let bytes = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    Ok(Some(bytes.to_vec()))
}
