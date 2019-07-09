package com.backbase.identity.testapp.repository;

import com.backbase.identity.testapp.entity.DataEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DataRepository extends CrudRepository<DataEntity, Integer> {

}
