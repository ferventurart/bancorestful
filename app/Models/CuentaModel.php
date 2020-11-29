<?php namespace App\Models;

use CodeIgniter\Model;

class CuentaModel extends Model 
{
    protected $table            = 'cuenta';
    protected $primaryKey       = 'id';

    protected $returnType       = 'array';
    protected $allowedFields    = ['moneda', 'fondo', 'cliente_id'];

    protected $useTimestamps    = true;
    protected $createdField     = 'created_at';
    protected $updatedField     = 'updated_at';

    protected $validationRules  = [
        'moneda'      => 'required|alpha_space|min_length[3]|max_length[3]|is_valid_currency',
        'fondo'       => 'required|numeric',
        'cliente_id'  => 'required|integer|is_valid_cliente', 
    ];

    protected $validationMessages = [
        'cliente_id'      => [
            'is_valid_cliente' => 'Estimado usuario, debe ingresar un cliente valido'
        ],
        'moneda'      => [
            'is_valid_currency' => 'Estimado usuario, debe ingresar una moneda valida'
        ]
    ];

    protected $skipValidation = false;
}