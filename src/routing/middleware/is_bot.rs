use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use http::header::USER_AGENT;
use isbot::Bots;

#[derive(Clone, Debug)]
pub struct IsBot(pub bool);

pub struct IsBotState {
    bots: Bots,
}

impl Default for IsBotState {
    fn default() -> Self {
        let mut bots = Bots::default();
        bots.append(&["GoogleOther"]);

        Self { bots }
    }
}

impl IsBotState {
    pub fn is_bot(&self, ua: &str) -> bool {
        self.bots.is_bot(ua)
    }
}

pub async fn middleware(
    State(state): State<Arc<IsBotState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let ua = request
        .headers()
        .get(USER_AGENT)
        .and_then(|x| x.to_str().ok());

    let is_bot = IsBot(ua.is_some_and(|x| state.is_bot(x)));
    request.extensions_mut().insert(is_bot);

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_bot() {
        let state = IsBotState::default();

        let bots = &[
            "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/W.X.Y.Z Safari/537.36",
            "Googlebot-Image/1.0",
            "Googlebot-Video/1.0",
            "Mozilla/5.0 (X11; Linux x86_64; Storebot-Google/1.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Safari/537.36",
            "Mozilla/5.0 (Linux; Android 8.0; Pixel 2 Build/OPD3.170816.012; Storebot-Google/1.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36",
            "Mozilla/5.0 (compatible; Google-InspectionTool/1.0;)",
            "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; Google-InspectionTool/1.0;)",
            "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; GoogleOther)",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.3; +https://openai.com/gptbot)",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36; compatible; OAI-SearchBot/1.3; +https://openai.com/searchbot",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
        ];

        for ua in bots {
            assert!(state.is_bot(ua));
        }

        let browsers = &[
            "Mozilla/5.0 (Linux; Android 15; SM-S931B Build/AP3A.240905.015.A2; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/127.0.6533.103 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 15; SM-S931U Build/AP3A.240905.015.A2; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/132.0.6834.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Android 15; Mobile; SM-G556B/DS; rv:130.0) Gecko/130.0 Firefox/130.0",
            "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
        ];

        for ua in browsers {
            assert!(!state.is_bot(ua));
        }
    }
}
