const adminModel = require("../models/adminModel");
const { responseReturn } = require("../utilities/response");
const bcrypt = require("bcrypt");
const { createToken } = require("../utilities/tokenCreate"); // Importar la función de manera correcta

class authcontrollers {
  admin_login = async (req, res) => {
    const { email, password } = req.body;
    try {
      const admin = await adminModel.findOne({ email }).select("+password");

      if (admin) {
        const match = await bcrypt.compare(password, admin.password);
        if (match) {
          const token = await createToken({
            id: admin?.id,
            role: admin?.role,
          });
          res.cookie("accesTokenEcommerce", token, {
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          });
          responseReturn(res, 200, { token, message: "Acceso correcto" });
        } else {
          responseReturn(res, 404, { error: "Contraseña incorrecta" });
        }
      } else {
        responseReturn(res, 404, {
          error: "El correo y/o contraseña son incorrectos",
        });
      }
    } catch (error) {
      responseReturn(res, 500, { error: error.message });
    }
  };
}

module.exports = new authcontrollers();
