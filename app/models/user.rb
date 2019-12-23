class User < ApplicationRecord
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i

  attr_accessor :remember_token, :activation_token

  before_save :downcase_email
  before_create :create_activation_digest

  validates :name, presence: true, length: {maximum: 50}
  validates :email,
            presence: true,
            length: {maximum: 255},
            format: { with: VALID_EMAIL_REGEX},
            uniqueness: { case_sensitive: false }
  validates :password, length: { minimum: 6 }, presence: true, allow_nil: true

  has_secure_password

  def remember
    self.remember_token = User.new_token
    update_attribute(:remember_digest, User.digest(remember_token))
  end

  def forget
    update_attribute(:remember_digest, nil)
  end

  # Returns true if the given token matches the digest.
  def authenticated?(attribute, token)
    digest = send("#{attribute}_digest")
    return false if digest.nil?
    BCrypt::Password.new(digest).is_password?(token)
  end

  # Returns the hash digest of the given string.
  def self.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                  BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
  end

  # Returns a random token
  def self.new_token
    SecureRandom.urlsafe_base64
  end

  # Activates an account.
  def activate
    update_columns(activated: true, activated_at: Time.zone.now)
  end

  # Sends activation email.
  def send_activation_email
    UserMailer.account_activation(self).deliver_now
  end

  # Converts email to all lower-case.
  private def downcase_email
    email.downcase!
  end

  private def create_activation_digest
    self.activation_token  = User.new_token
    self.activation_digest = User.digest(activation_token)  end
end
