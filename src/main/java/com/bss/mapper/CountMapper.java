package com.bss.mapper;

import com.bss.entity.ChartCount;
import com.bss.entity.RecordCount;
import com.bss.entity.RecordNum;
import com.bss.entity.StockNum;
import com.bss.entity.User;
import java.util.List;
import java.util.Map;

public interface CountMapper {
  List<RecordNum> getCount(Map<String, Object> paramMap);
  
  List<RecordCount> getCountByUid(Map<String, Object> paramMap);
  
  List<StockNum> stockCount(Map<String, Object> paramMap);
  
  List<RecordNum> superRecordCount(List<User> paramList);
  
  List<ChartCount> getMemberCount(Map<String, Object> paramMap);
  
  List<ChartCount> getRecordCount(Map<String, Object> paramMap);
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\mapper\CountMapper.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */