//! WebSocket endpoint for real-time alerts

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::Response,
};
use futures::{sink::SinkExt, stream::StreamExt};
use tracing::{debug, error, info};

use crate::api::{ApiState, WebSocketMessage};

/// WebSocket handler
pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<ApiState>) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

/// Handle WebSocket connection
async fn handle_socket(socket: WebSocket, state: ApiState) {
    info!("New WebSocket connection established");

    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.ws_tx.subscribe();

    // Spawn task to forward broadcast messages to this client
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            let json = match serde_json::to_string(&msg) {
                Ok(j) => j,
                Err(e) => {
                    error!("Failed to serialize WebSocket message: {}", e);
                    continue;
                }
            };

            if let Err(e) = sender.send(axum::extract::ws::Message::Text(json)).await {
                error!("WebSocket send error: {}", e);
                break;
            }
        }
    });

    // Spawn task to handle incoming messages (pings, etc.)
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                axum::extract::ws::Message::Text(text) => {
                    debug!("Received WebSocket message: {}", text);
                    // Handle client messages if needed
                }
                axum::extract::ws::Message::Close(_) => {
                    info!("WebSocket client disconnected");
                    break;
                }
                axum::extract::ws::Message::Ping(_) => {
                    // Axum handles pongs automatically
                }
                _ => {}
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = (&mut send_task) => {
            recv_task.abort();
        }
        _ = (&mut recv_task) => {
            send_task.abort();
        }
    }

    info!("WebSocket connection closed");
}
