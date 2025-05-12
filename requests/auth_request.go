package requests

import (
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

type LoginRequest struct {
	Account  string `json:"account" form:"account" validate:"required,min=3"`
	Password string `json:"password" form:"password" validate:"required,min=6"`
}

func ValidateLoginRequest(c *fiber.Ctx) error {
	var req LoginRequest

	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Geçersiz istek formatı")
	}

	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			switch {
			case err.Field() == "Account" && err.Tag() == "required":
				return fiber.NewError(fiber.StatusBadRequest, "Kullanıcı adı zorunludur")
			case err.Field() == "Password" && err.Tag() == "required":
				return fiber.NewError(fiber.StatusBadRequest, "Şifre zorunludur")
			case err.Field() == "Password" && err.Tag() == "min":
				return fiber.NewError(fiber.StatusBadRequest, "Şifre en az 6 karakter olmalıdır")
			default:
				return fiber.NewError(fiber.StatusBadRequest, "Geçersiz giriş bilgileri")
			}
		}
	}

	c.Locals("loginRequest", req)
	return c.Next()
}

type UpdatePasswordRequest struct {
	CurrentPassword string `form:"current_password" validate:"required,min=6"`
	NewPassword     string `form:"new_password" validate:"required,min=8,nefield=CurrentPassword"`
	ConfirmPassword string `form:"confirm_password" validate:"required,eqfield=NewPassword"`
}

func ValidateUpdatePasswordRequest(c *fiber.Ctx) error {
	var req UpdatePasswordRequest

	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Geçersiz istek formatı")
	}

	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			switch {
			case err.Field() == "CurrentPassword" && err.Tag() == "required":
				return fiber.NewError(fiber.StatusBadRequest, "Mevcut şifre zorunludur")
			case err.Field() == "CurrentPassword" && err.Tag() == "min":
				return fiber.NewError(fiber.StatusBadRequest, "Mevcut şifre en az 6 karakter olmalıdır")
			case err.Field() == "NewPassword" && err.Tag() == "required":
				return fiber.NewError(fiber.StatusBadRequest, "Yeni şifre zorunludur")
			case err.Field() == "NewPassword" && err.Tag() == "min":
				return fiber.NewError(fiber.StatusBadRequest, "Yeni şifre en az 8 karakter olmalıdır")
			case err.Field() == "NewPassword" && err.Tag() == "nefield":
				return fiber.NewError(fiber.StatusBadRequest, "Yeni şifre mevcut şifreden farklı olmalıdır")
			case err.Field() == "ConfirmPassword" && err.Tag() == "required":
				return fiber.NewError(fiber.StatusBadRequest, "Şifre tekrarı zorunludur")
			case err.Field() == "ConfirmPassword" && err.Tag() == "eqfield":
				return fiber.NewError(fiber.StatusBadRequest, "Yeni şifreler uyuşmuyor")
			default:
				return fiber.NewError(fiber.StatusBadRequest, "Geçersiz şifre bilgileri")
			}
		}
	}

	c.Locals("updatePasswordRequest", req)
	return c.Next()
}
