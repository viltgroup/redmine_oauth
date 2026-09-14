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

# OauthProvider model class
class OauthProvider < ApplicationRecord
  BUTTON_IMAGE_MAX_SIZE = 256.kilobytes
  BUTTON_IMAGE_TYPES = %w[image/png image/jpeg image/gif image/svg+xml image/webp].freeze

  # Holds the uploaded file until before_validation turns it into a data URI
  attr_accessor :button_image_upload

  before_validation :store_button_image

  validates :oauth_name, presence: true
  validates :site, format: { without: /\.ru\b/ }, length: { maximum: 256 }
  validates :client_id, presence: true, length: { maximum: 256 }
  validates :client_secret, presence: true, length: { maximum: 128 } # Must be longer due to an optional cyphering
  validates :tenant_id, length: { maximum: 40 }
  validates :custom_name, presence: true, uniqueness: true, length: { maximum: 30 }
  validates :custom_auth_endpoint, length: { maximum: 256 }
  validates :custom_auth_endpoint, presence: true, if: proc { |p| p.custom_name == 'Custom' }
  validates :custom_token_endpoint, length: { maximum: 256 }
  validates :custom_token_endpoint, presence: true, if: proc { |p| p.custom_name == 'Custom' }
  validates :custom_profile_endpoint, length: { maximum: 256 }
  validates :custom_scope, length: { maximum: 256 }
  validates :custom_uid_field, length: { maximum: 40 }
  validates :custom_email_field, length: { maximum: 40 }
  validates :custom_firstname_field, length: { maximum: 30 }
  validates :custom_lastname_field, length: { maximum: 30 }
  validates :custom_logout_endpoint, length: { maximum: 80 }
  validates :validate_user_roles, length: { maximum: 40 }
  validates :url_parameters, length: { maximum: 128 }, if: proc { has_attribute?(:url_parameters) }
  validates :button_text, length: { maximum: 40 }, if: proc { has_attribute?(:button_text) }

  scope :sorted, -> { order(:position) }

  def update_from_parameters(params)
    self.oauth_name = params['oauth_name']
    self.site = params['site']
    self.client_id = params['client_id']
    self.client_secret = Redmine::Ciphering.encrypt_text(params['client_secret'])
    self.tenant_id = params['tenant_id']
    self.custom_name = params['custom_name']
    self.custom_auth_endpoint = params['custom_auth_endpoint']
    self.custom_token_endpoint = params['custom_token_endpoint']
    self.custom_profile_endpoint = params['custom_profile_endpoint']
    self.custom_scope = params['custom_scope']
    self.custom_uid_field = params['custom_uid_field']
    self.custom_email_field = params['custom_email_field']
    self.button_color = params['button_color']
    self.button_icon = params['button_icon']
    self.button_image = nil if params['button_image_delete'] == '1'
    self.button_image_upload = params['button_image_upload']
    self.custom_firstname_field = params['custom_firstname_field']
    self.custom_lastname_field = params['custom_lastname_field']
    self.custom_logout_endpoint = params['custom_logout_endpoint']
    self.validate_user_roles = params['validate_user_roles']
    self.enable_group_roles = params['enable_group_roles']
    self.oauth_version = params['oauth_version']
    self.identify_user_by = params['identify_user_by']
    self.imap = params['imap']
    self.url_parameters = params['url_parameters']
    self.button_text = params['button_text']
    # Reset IMAP by other providers
    OauthProvider.where.not(id: id).where(imap: true).update(imap: false) if imap
  end

  private

  # The image is kept inline as a data URI. That spares a storage path and a route to serve it from,
  # and the login page needs the bytes on every render anyway.
  def store_button_image
    upload = button_image_upload
    return if upload.blank?

    unless BUTTON_IMAGE_TYPES.include?(upload.content_type)
      errors.add :button_image, :invalid
      return
    end

    upload.rewind
    content = upload.read
    if content.bytesize > BUTTON_IMAGE_MAX_SIZE
      errors.add :button_image, I18n.t(:error_oauth_button_image_too_big, max: BUTTON_IMAGE_MAX_SIZE / 1024)
      return
    end

    self.button_image = "data:#{upload.content_type};base64,#{Base64.strict_encode64(content)}"
  end
end
