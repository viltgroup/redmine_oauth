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

# The provider session behind a Redmine session. With the token check on, the refresh token is redeemed whenever the
# access token is due, and a refused refresh ends the Redmine session too, so the provider's own session limits
# (Keycloak's SSO Session Idle and Max, a logout elsewhere, a disabled account) apply to Redmine.
class OauthSession < ApplicationRecord
  belongs_to :user
  belongs_to :oauth_provider

  # Assumed access token lifetime when the provider does not send expires_in
  DEFAULT_LIFETIME = 5.minutes
  # How long a session is trusted while the provider cannot be reached, before it is asked again
  RETRY_AFTER = 1.minute
  # Records that have not been refreshed for this long belong to sessions that are gone
  STALE_AFTER = 30.days
  # Keep a slow provider from holding up a page for long
  TIMEOUT = 5

  scope :stale, -> { where(updated_at: ...STALE_AFTER.ago) }

  def self.start(user_id, oauth_provider, token)
    stale.delete_all
    oauth_session = new(user_id: user_id, oauth_provider: oauth_provider)
    oauth_session.store token
    oauth_session.save!
    oauth_session
  end

  def refresh_token
    Redmine::Ciphering.decrypt_text(self[:refresh_token])
  end

  def refresh_token=(value)
    self[:refresh_token] = value.presence && Redmine::Ciphering.encrypt_text(value)
  end

  def expired?
    expires_at.nil? || expires_at <= Time.current
  end

  # False only when the provider has refused the refresh. The row is locked meanwhile, so that parallel requests of
  # one session do not redeem the same refresh token twice, which a provider that rotates them would treat as a replay.
  def alive?
    # A provider that issues no refresh token cannot be asked
    return true if self[:refresh_token].blank?
    return true unless expired?

    alive = with_lock { expired? ? refresh : true }
    destroy unless alive
    alive
  end

  def store(token)
    self.refresh_token = token.refresh_token
    self.expires_at = token.expires_at ? Time.zone.at(token.expires_at) : DEFAULT_LIFETIME.from_now
  end

  private

  def refresh
    return false unless oauth_provider

    client = RedmineOauth::OauthClient.client(oauth_provider)
    client.options[:connection_opts] = { request: { open_timeout: TIMEOUT, timeout: TIMEOUT } }
    store OAuth2::AccessToken.new(client, nil, refresh_token: refresh_token).refresh
    save!
    true
  rescue OAuth2::Error => e
    return unreachable(e) if e.response&.status.to_i >= 500

    Rails.logger.info "OAuth session of user #{user_id} ended by #{oauth_provider.custom_name}: #{e.code}"
    false
  rescue Faraday::Error => e
    unreachable e
  end

  # A provider outage must not log everybody out, so the session is kept and the provider asked again shortly
  def unreachable(error)
    Rails.logger.warn "OAuth session of user #{user_id} not checked, #{oauth_provider.custom_name} unreachable: " \
                      "#{error.message}"
    update_columns expires_at: RETRY_AFTER.from_now
    true
  end
end
