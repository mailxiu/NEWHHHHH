package com.bss.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.bss.entity.Stock;
import java.util.Map;

public interface StockMapper extends BaseMapper<Stock> {
  IPage<Stock> selectPageVo(Page<?> paramPage, Map<String, Object> paramMap);
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\mapper\StockMapper.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */