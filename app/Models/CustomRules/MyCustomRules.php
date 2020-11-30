<?php

namespace App\Models\CustomRules;

use App\Models\ClienteModel;
use App\Models\CuentaModel;
use App\Models\RolModel;
use App\Models\TipoTransaccionModel;

class MyCustomRules
{
    public function is_valid_cliente(int $id): bool
    {
        $model = new ClienteModel();
        $cliente = $model->find($id);

        return $cliente == null ? false : true;
    }

    public function is_valid_currency(string $moneda): bool
    {
        switch ($moneda):
            case 'USD':
                return true;
                break;

            case 'EUR':
                return true;
                break;

            default:
                return false;
                break;
        endswitch;
    }

    public function is_valid_cuenta(int $id): bool
    {
        $model = new CuentaModel();
        $cuenta = $model->find($id);

        return $cuenta == null ? false : true;
    }

    public function is_valid_tipo_transaccion(int $id): bool
    {
        $model = new TipoTransaccionModel();
        $tipotransaccion = $model->find($id);

        return $tipotransaccion == null ? false : true;
    }

    public function is_valid_rol(int $id): bool
    {
        $model = new RolModel();
        $rol = $model->find($id);

        return $rol == null ? false : true;
    }
}
