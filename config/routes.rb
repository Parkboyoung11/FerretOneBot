Rails.application.routes.draw do
  post "event_handler", to: "bot#handle_github_event"
end
