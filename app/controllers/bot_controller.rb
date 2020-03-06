class BotController < ApplicationController
  before_action :authen_confirm

  PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']

  def handle_github_event
    case request.env['HTTP_X_GITHUB_EVENT']
    when 'pull_request'
      handle_pull_request_opened_event(@payload) if @payload['action'] === 'opened'
      handle_label_added_event(@payload) if @payload['action'] == 'labeled'
    end
    render html: '<div>FO bot !!!</div>'.html_safe
  end

  private

  def authen_confirm
    get_payload_request(request)
    verify_webhook_signature
    authenticate_app
    authenticate_installation(@payload)
  end

  def handle_pull_request_opened_event(payload)
    repo = payload['repository']['full_name']
    pull_request_number = payload['pull_request']['number']
    head = payload['pull_request']['head']['ref']
    base = payload['pull_request']['base']['ref']
    if(head == ENV['KANARIA_HEAD'] && base == ENV['KANARIA_BASE'])
      comment_content = get_issue_content(repo, ENV['ISSUE_KANARIA_NUMBER'])
      @installation_client.add_comment(repo, pull_request_number, comment_content) 
    end
  end

  def handle_label_added_event(payload)
    repo = payload['repository']['full_name']
    pull_request_number = payload['pull_request']['number']
    label = payload['label']['name']
    if label == ENV['LABEL_PAIR_REVIEW']
      comment_content = get_issue_content(repo, ENV['ISSUE_PAIR_REVIEW_NUMBER'])
      @installation_client.add_comment(repo, pull_request_number, comment_content)
    end
  end

  def get_issue_content(repo, issue_number)
    result = @installation_client.issue(repo, issue_number)
    return result.body
  end

  def get_payload_request(request)
    request.body.rewind
    @payload_raw = request.body.read
    begin
      @payload = JSON.parse @payload_raw
    rescue => e
      fail  "Invalid JSON (#{e}): #{@payload_raw}"
    end
  end

  def authenticate_app
    payload = {
        iat: Time.now.to_i,
        exp: Time.now.to_i + (10 * 60),
        iss: APP_IDENTIFIER
    }

    jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')
    @app_client ||= Octokit::Client.new(bearer_token: jwt)
  end

  def authenticate_installation(payload)
    @installation_id = payload['installation']['id']
    @installation_token = @app_client.create_app_installation_access_token(@installation_id)[:token]
    @installation_client = Octokit::Client.new(bearer_token: @installation_token)
  end

  def verify_webhook_signature
    their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
    method, their_digest = their_signature_header.split('=')
    our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
    halt 401 unless their_digest == our_digest

    logger.debug "---- received event #{request.env['HTTP_X_GITHUB_EVENT']}"
    logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
  end
end
