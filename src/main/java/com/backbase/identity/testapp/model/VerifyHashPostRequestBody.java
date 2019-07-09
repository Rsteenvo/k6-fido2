package com.backbase.identity.testapp.model;

import javax.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class VerifyHashPostRequestBody {

    @NotNull
    private Integer id;

    @NotNull
    private String hash;

}
