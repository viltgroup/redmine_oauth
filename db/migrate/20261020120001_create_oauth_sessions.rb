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

# The provider session behind each Redmine session, for the token check. Kept in the database rather than in Redmine's
# cookie session, which is limited to 4 KB and could not hold a provider's tokens.
class CreateOauthSessions < ActiveRecord::Migration[7.2]
  def change
    create_table :oauth_sessions do |t|
      t.integer :user_id, null: false
      t.integer :oauth_provider_id, null: false
      t.text :refresh_token
      t.datetime :expires_at
      t.timestamps
      t.index :user_id
      t.index :updated_at
    end
  end
end
