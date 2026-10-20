# frozen_string_literal: true

# Redmine plugin OAuth
#
# Karel Pičman <karel.picman@kontron.com>
#
# This file is part of Redmine OAuth plugin.
#
# Redmine OAuth plugin is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# Redmine OAuth plugin is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
# the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with Redmine OAuth plugin. If not, see
# <https://www.gnu.org/licenses/>.

require File.expand_path('../../integration_test', __FILE__)

# Token check
class TokenCheckTest < RedmineOAuth::Test::IntegrationTest
  include Redmine::I18n

  def setup
    super
    @oauth_provider = OauthProvider.find(1)
  end

  def test_login_without_token_check
    with_token_check false do
      oauth_login
      assert_equal 0, OauthSession.count
      assert_logged_in
    end
  end

  def test_login_with_token_check
    with_token_check do
      oauth_login
      oauth_session = OauthSession.sole
      assert_equal 'refresh-1', oauth_session.refresh_token
      assert_equal User.find_by(login: 'jsmith').id, oauth_session.user_id
      # The access token is not due yet, so the provider is not asked
      OAuth2::AccessToken.any_instance.expects(:refresh).never
      assert_logged_in
    end
  end

  def test_refresh_when_access_token_is_due
    with_token_check do
      oauth_login
      oauth_session = OauthSession.sole
      oauth_session.update_columns expires_at: 1.minute.ago
      OAuth2::AccessToken.any_instance.expects(:refresh).once.returns(access_token(refresh_token: 'refresh-2'))
      assert_logged_in
      oauth_session.reload
      assert_equal 'refresh-2', oauth_session.refresh_token
      assert oauth_session.expires_at > 4.minutes.from_now
    end
  end

  def test_refused_refresh_logs_out
    with_token_check do
      oauth_login
      OauthSession.sole.update_columns expires_at: 1.minute.ago
      OAuth2::AccessToken.any_instance.stubs(:refresh).raises(oauth_error(400, 'invalid_grant'))
      assert_logged_out
      assert_equal 0, OauthSession.count
      assert_equal l(:error_session_expired), flash[:error]
    end
  end

  def test_unreachable_provider_keeps_session
    with_token_check do
      oauth_login
      oauth_session = OauthSession.sole
      oauth_session.update_columns expires_at: 1.minute.ago
      OAuth2::AccessToken.any_instance.stubs(:refresh).raises(Faraday::ConnectionFailed.new('down'))
      assert_logged_in
      assert oauth_session.reload.expires_at > Time.current
    end
  end

  def test_provider_error_keeps_session
    with_token_check do
      oauth_login
      OauthSession.sole.update_columns expires_at: 1.minute.ago
      OAuth2::AccessToken.any_instance.stubs(:refresh).raises(oauth_error(503, 'unavailable'))
      assert_logged_in
    end
  end

  def test_provider_without_refresh_token_is_not_checked
    with_token_check do
      oauth_login access_token(refresh_token: nil)
      OauthSession.sole.update_columns expires_at: 1.minute.ago
      OAuth2::AccessToken.any_instance.expects(:refresh).never
      assert_logged_in
    end
  end

  def test_oauth_session_started_before_token_check_ends
    with_token_check(false) { oauth_login }
    with_token_check do
      assert_logged_out
    end
  end

  def test_password_login_is_not_checked
    with_token_check do
      log_user 'jsmith', 'jsmith'
      assert_logged_in
    end
  end

  def test_sso_forced_account_without_oauth_session_logs_out
    with_token_check(false) { log_user 'jsmith', 'jsmith' }
    with_token_check(true, 'sso_forced_domains' => 'somenet.foo') do
      assert_logged_out
    end
  end

  def test_logout_deletes_oauth_session
    with_token_check do
      oauth_login
      post '/logout'
      assert_equal 0, OauthSession.count
    end
  end

  def test_stale_oauth_sessions_are_purged_on_login
    with_token_check do
      stale = OauthSession.create!(user_id: 1, oauth_provider: @oauth_provider, refresh_token: 'old')
      stale.update_columns updated_at: 31.days.ago
      oauth_login
      assert_not OauthSession.exists?(stale.id)
    end
  end

  def test_refresh_token_is_stored_through_ciphering
    Redmine::Configuration.with 'database_cipher_key' => 'secret' do
      oauth_session = OauthSession.create!(user_id: 1, oauth_provider: @oauth_provider, refresh_token: 'plain')
      assert_not_equal 'plain', oauth_session.read_attribute(:refresh_token)
      assert_equal 'plain', oauth_session.reload.refresh_token
    end
  end

  private

  def with_token_check(enabled = true, settings = {}, &)
    with_settings(plugin_redmine_oauth: { 'token_check' => enabled ? '1' : '0' }.merge(settings), &)
  end

  def access_token(refresh_token: 'refresh-1')
    claims = { 'preferred_username' => 'jsmith', 'email' => 'jsmith@somenet.foo', 'name' => 'John Smith' }
    OAuth2::AccessToken.new(OAuth2::Client.new('id', 'secret'), JWT.encode(claims, nil, 'none'),
                            refresh_token: refresh_token, expires_in: 300)
  end

  def oauth_error(status, code)
    OAuth2::Error.new(OAuth2::Response.new(Faraday::Response.new(status: status, body: { error: code }.to_json,
                                                                  response_headers: { 'Content-Type' =>
                                                                                      'application/json' })))
  end

  def oauth_login(token = access_token)
    OAuth2::Strategy::AuthCode.any_instance.stubs(:get_token).returns(token)
    get "/oauth?oauth_provider=#{@oauth_provider.id}"
    state = Rack::Utils.parse_query(URI.parse(response.location).query)['state']
    get '/oauth2callback', params: { code: 'code', state: state }
    assert_redirected_to '/my/page'
  end

  def assert_logged_in
    get '/my/page'
    assert_response :success
  end

  def assert_logged_out
    get '/my/page'
    assert_redirected_to %r{/login}
  end
end
